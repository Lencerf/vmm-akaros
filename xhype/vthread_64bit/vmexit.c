#include "vmexit.h"

#include <stdbool.h>
#include <stdio.h>
#include <sys/sysctl.h>

#include "cpuid.h"
#include "lapic.h"
#include "stdbool.h"
#include "utils.h"
#include "x86.h"

const uint64_t cr0_ones_mask = (X86_CR0_NE | X86_CR0_ET);
const uint64_t cr0_zeros_mask = (X86_CR0_NW | X86_CR0_CD);

int vmm_handle_move_cr(hv_vcpuid_t vcpu) {
  uint64_t qual = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
  struct vmexit_qual_cr* qual_cr = (struct vmexit_qual_cr*)&qual;
  if (qual_cr->cr_num == 0) {
    if (qual_cr->type == VMEXIT_QUAL_CR_TYPE_MOVETO) {
      uint64_t regval = vmx_get_guest_reg(vcpu, qual_cr->g_reg);
      printf("regval = %llx\n", regval);
      regval |= cr0_ones_mask;
      regval &= ~cr0_zeros_mask;
      wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW, regval);
      wvmcs(vcpu, VMCS_GUEST_CR0, regval);
      uint64_t efer = rvmcs(vcpu, VMCS_GUEST_IA32_EFER);
      if ((regval & X86_CR0_PG) && (efer & EFER_LME)) {
        printf("turn on paging\n");
        efer |= EFER_LMA;
        wvmcs(vcpu, VMCS_GUEST_IA32_EFER, efer);
        uint64_t ctrl_entry = rvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS);
        wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS,
              ctrl_entry | VMENTRY_GUEST_IA32E);
      } else if (!(regval & X86_CR0_PG) && (efer & EFER_LMA)) {
        printf("turn off paging\n");
        efer &= ~EFER_LMA;
        wvmcs(vcpu, VMCS_GUEST_IA32_EFER, efer);
        uint64_t ctrl_entry = rvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS);
        wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS,
              ctrl_entry & ~VMENTRY_GUEST_IA32E);
      }
    } else {
      print_red("qual_cr->type = %llx\n", qual_cr->type);
      return VMEXIT_STOP;
    }
  } else if (qual_cr->cr_num == 4) {
    if (qual_cr->type == VMEXIT_QUAL_CR_TYPE_MOVETO) {
      uint64_t regval = vmx_get_guest_reg(vcpu, qual_cr->g_reg);
      wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, regval);
      wvmcs(vcpu, VMCS_GUEST_CR4, regval);
      printf("update cr4 to %llx\n", regval);
    } else {
      print_red("qual_cr->type = %llx\n", qual_cr->type);
      return VMEXIT_STOP;
    }
  } else if (qual_cr->cr_num == 8) {
    return VMEXIT_STOP;
  }
  return VMEXIT_NEXT;
}

typedef int (*mmio_reader)(uint64_t, int, uint64_t*);
typedef int (*mmio_writer)(uint64_t, int, const uint64_t*);

int vmm_emulate_instruction(hv_vcpuid_t vcpu, uint64_t gpa, mmio_reader reader,
                            mmio_writer writer) {
  // FIX ME: not finished
  return VMEXIT_STOP;
}

int vmm_handle_mmio(hv_vcpuid_t vcpu) {
  uint64_t gpa = rvmcs(vcpu, VMCS_GUEST_PHYSICAL_ADDRESS);
  mmio_reader reader;
  mmio_writer writer;
  if (gpa >= APIC_BASE && gpa < APIC_BASE + PAGE_SIZE) {
    reader = lapic_mmio_read;
    writer = lapic_mmio_write;
  } else {
    return VMEXIT_STOP;
  }
  return vmm_emulate_instruction(vcpu, gpa, reader, writer);
}

void vmm_exit_init() {
  vmx_msr_init();
  vmm_host_state_init();
  vmexit_io_init();  // FIX ME
}