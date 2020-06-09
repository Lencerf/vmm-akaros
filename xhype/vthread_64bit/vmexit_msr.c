#include "vmexit_msr.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>

#include "utils.h"
#include "vmexit.h"
#include "x86.h"

uint64_t misc_enable;
uint64_t platform_info;
uint64_t turbo_ratio_limit;

void vmx_msr_init(void) {
  uint64_t bus_freq, tsc_freq, ratio;
  size_t length;
  int i;

  length = sizeof(uint64_t);
  GUARD(sysctlbyname("machdep.tsc.frequency", &tsc_freq, &length, NULL, 0), 0)
  GUARD(sysctlbyname("hw.busfrequency", &bus_freq, &length, NULL, 0), 0);

  /* Initialize emulated MSRs */
  /* FIXME */
  misc_enable = 1;
  /*
   * Set mandatory bits
   *  11:   branch trace disabled
   *  12:   PEBS unavailable
   * Clear unsupported features
   *  16:   SpeedStep enable
   *  18:   enable MONITOR FSM
   */
  misc_enable |= (1u << 12) | (1u << 11);
  misc_enable &= ~((1u << 18) | (1u << 16));

  /*
   * XXXtime
   * The ratio should really be based on the virtual TSC frequency as
   * opposed to the host TSC.
   */
  ratio = (tsc_freq / bus_freq) & 0xff;

  /*
   * The register definition is based on the micro-architecture
   * but the following bits are always the same:
   * [15:8]  Maximum Non-Turbo Ratio
   * [28]    Programmable Ratio Limit for Turbo Mode
   * [29]    Programmable TDC-TDP Limit for Turbo Mode
   * [47:40] Maximum Efficiency Ratio
   *
   * The other bits can be safely set to 0 on all
   * micro-architectures up to Haswell.
   */
  platform_info = (ratio << 8) | (ratio << 40);

  /*
   * The number of valid bits in the MSR_TURBO_RATIO_LIMITx register is
   * dependent on the maximum cores per package supported by the micro-
   * architecture. For e.g., Westmere supports 6 cores per package and
   * uses the low 48 bits. Sandybridge support 8 cores per package and
   * uses up all 64 bits.
   *
   * However, the unused bits are reserved so we pretend that all bits
   * in this MSR are valid.
   */
  for (i = 0; i < 8; i++) {
    turbo_ratio_limit = (turbo_ratio_limit << 8) | ratio;
  }
}

int vmm_handle_rdmsr(hv_vcpuid_t vcpu) {
  uint64_t rcx = rreg(vcpu, HV_X86_RCX);
  uint64_t value;
  if (rcx == MSR_EFER) {
    value = rvmcs(vcpu, VMCS_GUEST_IA32_EFER);
    printf("efer= %llx to guest\n", value);
  } else if (rcx == MSR_MCG_CAP || rcx == MSR_MCG_STATUS ||
             rcx == MSR_MTRRcap || rcx == MSR_MTRRdefType ||
             (rcx >= MSR_MTRR4kBase && rcx <= MSR_MTRR4kBase + 8) ||
             rcx == MSR_MTRR16kBase || rcx == MSR_MTRR16kBase + 1 ||
             rcx == MSR_MTRR64kBase || rcx == MSR_BIOS_SIGN ||
             rcx == MSR_IA32_PLATFORM_ID || rcx == MSR_PKG_ENERGY_STATUS ||
             rcx == MSR_PP0_ENERGY_STATUS || rcx == MSR_PP1_ENERGY_STATUS ||
             rcx == MSR_DRAM_ENERGY_STATUS) {
    value = 0;
  } else if (rcx == MSR_IA32_MISC_ENABLE) {
    value = misc_enable;
  } else if (rcx == MSR_PLATFORM_INFO) {
    value = platform_info;
  } else if (rcx == MSR_TURBO_RATIO_LIMIT || rcx == MSR_TURBO_RATIO_LIMIT1) {
    value = turbo_ratio_limit;
  } else {
    printf("read unknow msr: %llx\n", rcx);
    return VMEXIT_STOP;
  }
  uint32_t new_eax = (uint32_t)(value & ~0Ul);
  uint32_t new_edx = (uint32_t)(value >> 32);
  wreg(vcpu, HV_X86_RAX, new_eax);
  wreg(vcpu, HV_X86_RDX, new_edx);
  return VMEXIT_NEXT;
}

int vmm_handle_wrmsr(hv_vcpuid_t vcpu) {
  uint64_t rax = rreg(vcpu, HV_X86_RAX);
  uint64_t rcx = rreg(vcpu, HV_X86_RCX);
  uint64_t rdx = rreg(vcpu, HV_X86_RDX);
  if (rcx == MSR_EFER) {
    uint64_t new_msr = ((uint64_t)rdx << 32) | rax;
    wvmcs(vcpu, VMCS_GUEST_IA32_EFER, new_msr);
    printf("write %llx to efer\n", new_msr);
  } else if (rcx == MSR_MCG_CAP || rcx == MSR_MCG_STATUS ||
             rcx == MSR_MTRRdefType ||
             (rcx >= MSR_MTRR4kBase && rcx <= MSR_MTRR4kBase + 8) ||
             rcx == MSR_MTRR16kBase || rcx == MSR_MTRR16kBase + 1 ||
             rcx == MSR_MTRR64kBase || rcx == MSR_BIOS_SIGN ||
             rcx == MSR_BIOS_UPDT_TRIG) {
    printf("wrmsr %llx, do nothing\n", rcx);
    ;  // do nothing
  } else {
    printf("write unkown msr: %llx\n", rcx);
    return VMEXIT_STOP;
  }
  return VMEXIT_NEXT;
}