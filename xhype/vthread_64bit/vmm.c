#include "vmm.h"

#include <pthread.h>
#include <stdio.h>

#include "utils.h"
#include "vmexit.h"
#include "x86.h"

// #define TEMP32

void vmm_init() {
  GUARD(hv_vm_create(HV_VM_DEFAULT), HV_SUCCESS);
  vmm_exit_init();
}

void vm_init(struct virtual_machine* vm) {
  GUARD(hv_vm_space_create(&(vm->sid)), HV_SUCCESS);
}
#ifdef TEMP32
void vcpu_unpaged(hv_vcpuid_t vcpu, struct vm_trapframe* tf) {
  // the following codes are crucial for turning 64bit for the guest.
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_LSTAR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_CSTAR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_STAR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_SF_MASK, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_KGSBASE, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_GSBASE, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_FSBASE, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_CS_MSR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_ESP_MSR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_EIP_MSR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_TSC, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_IA32_TSC_AUX, 1), HV_SUCCESS);

  // setttup segment registers
  wvmcs(vcpu, VMCS_GUEST_CS, 0x10);
  wvmcs(vcpu, VMCS_GUEST_CS_AR, 0xc09b);  // Granularity,
  wvmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_CS_BASE, 0x0);

  wvmcs(vcpu, VMCS_GUEST_DS, 0x18);
  wvmcs(vcpu, VMCS_GUEST_DS_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_DS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_ES, 0x18);
  wvmcs(vcpu, VMCS_GUEST_ES_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_ES_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_FS, 0);
  wvmcs(vcpu, VMCS_GUEST_FS_AR, 0x93);
  wvmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xffff);
  wvmcs(vcpu, VMCS_GUEST_FS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_GS, 0);
  wvmcs(vcpu, VMCS_GUEST_GS_AR, 0x93);
  wvmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xffff);
  wvmcs(vcpu, VMCS_GUEST_GS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_SS, 0x18);
  wvmcs(vcpu, VMCS_GUEST_SS_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_SS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_LDTR, 0);
  wvmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x82);
  wvmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0xffff);
  wvmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_TR, 0);
  wvmcs(vcpu, VMCS_GUEST_TR_AR, 0x8b);
  wvmcs(vcpu, VMCS_GUEST_TR_LIMIT, 0);
  wvmcs(vcpu, VMCS_GUEST_TR_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, tf->gdt_limit);
  wvmcs(vcpu, VMCS_GUEST_GDTR_BASE, tf->gdt_base);

  wvmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);
  wvmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);

  uint64_t cap_pin, cap_cpu, cap_cpu2, cap_entry;
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &cap_pin), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &cap_cpu), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &cap_cpu2), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &cap_entry), HV_SUCCESS);
  wvmcs(vcpu, VMCS_CTRL_PIN_BASED, cap2ctrl(cap_pin, 0));
  wvmcs(vcpu, VMCS_CTRL_CPU_BASED,
        cap2ctrl(cap_cpu, CPU_BASED_HLT | CPU_BASED_CR8_LOAD |
                              CPU_BASED_CR8_STORE | CPU_BASED_MONITOR |
                              CPU_BASED_MWAIT));
  wvmcs(vcpu, VMCS_CTRL_CPU_BASED2, cap2ctrl(cap_cpu2, CPU_BASED2_RDTSCP));
  wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS, cap2ctrl(cap_entry, 0));

  wvmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0x40000);  // 0x40000
  // 0xffffffff

  uint64_t cr0 = X86_CR0_NE | X86_CR0_PE;  // turn on protection
  // cr0 |= X86_CR0_PG;                                    // turn on pageing
  wvmcs(vcpu, VMCS_GUEST_CR0, cr0);
  wvmcs(vcpu, VMCS_CTRL_CR0_MASK, 0xe0000031);
  wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW, cr0);

  wvmcs(vcpu, VMCS_GUEST_CR3, tf->cr3);

  uint64_t cr4 = X86_CR4_VMXE;
  // cr4 |= X86_CR4_PAE;  // turn on 64bit paging
  wvmcs(vcpu, VMCS_GUEST_CR4, cr4);
  // make the guest unable to find it running in a virtual machine
  wvmcs(vcpu, VMCS_CTRL_CR4_MASK, X86_CR4_VMXE);
  wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0);

  wreg(vcpu, HV_X86_RSI, tf->rsi);
  wreg(vcpu, HV_X86_RFLAGS, tf->rflags);
  wreg(vcpu, HV_X86_RDI, tf->rdi);
  wreg(vcpu, HV_X86_RBP, tf->rbp);
  wreg(vcpu, HV_X86_RBX, tf->rbx);

  wvmcs(vcpu, VMCS_GUEST_RIP, tf->rip);
}
#else
void vcpu_longmode(hv_vcpuid_t vcpu, struct vm_trapframe* tf) {
  // the following codes are crucial for turning 64bit for the guest.
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_LSTAR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_CSTAR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_STAR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_SF_MASK, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_KGSBASE, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_GSBASE, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_FSBASE, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_CS_MSR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_ESP_MSR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_SYSENTER_EIP_MSR, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_TSC, 1), HV_SUCCESS);
  GUARD(hv_vcpu_enable_native_msr(vcpu, MSR_IA32_TSC_AUX, 1), HV_SUCCESS);

  // setttup segment registers
  wvmcs(vcpu, VMCS_GUEST_CS, 0x10);
  wvmcs(vcpu, VMCS_GUEST_CS_AR, 0xa09b);  // Granularity, 64 bits flag
  wvmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_CS_BASE, 0x0);

  wvmcs(vcpu, VMCS_GUEST_DS, 0x18);
  wvmcs(vcpu, VMCS_GUEST_DS_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_DS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_ES, 0x18);
  wvmcs(vcpu, VMCS_GUEST_ES_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_ES_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_FS, 0);
  wvmcs(vcpu, VMCS_GUEST_FS_AR, 0x93);
  wvmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xffff);
  wvmcs(vcpu, VMCS_GUEST_FS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_GS, 0);
  wvmcs(vcpu, VMCS_GUEST_GS_AR, 0x93);
  wvmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xffff);
  wvmcs(vcpu, VMCS_GUEST_GS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_SS, 0x18);
  wvmcs(vcpu, VMCS_GUEST_SS_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_SS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_LDTR, 0);
  wvmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x82);
  wvmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0xffff);
  wvmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_TR, 0);
  wvmcs(vcpu, VMCS_GUEST_TR_AR, 0x8b);
  wvmcs(vcpu, VMCS_GUEST_TR_LIMIT, 0);
  wvmcs(vcpu, VMCS_GUEST_TR_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, tf->gdt_limit);
  wvmcs(vcpu, VMCS_GUEST_GDTR_BASE, tf->gdt_base);

  wvmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);
  wvmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);

  uint64_t cap_pin, cap_cpu, cap_cpu2, cap_entry;
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &cap_pin), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &cap_cpu), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &cap_cpu2), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &cap_entry), HV_SUCCESS);
  wvmcs(vcpu, VMCS_CTRL_PIN_BASED, cap2ctrl(cap_pin, 0));
  wvmcs(vcpu, VMCS_CTRL_CPU_BASED,
        cap2ctrl(cap_cpu, CPU_BASED_HLT | CPU_BASED_CR8_LOAD |
                              CPU_BASED_CR8_STORE | CPU_BASED_MONITOR |
                              CPU_BASED_MWAIT));
  wvmcs(vcpu, VMCS_CTRL_CPU_BASED2, cap2ctrl(cap_cpu2, CPU_BASED2_RDTSCP));
  wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS,
        cap2ctrl(cap_entry, VMENTRY_GUEST_IA32E));  // indicate that the guest
                                                    // will be in 64bit mode

  wvmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff & ~(1UL << 14));  // 0x40000
  // 0xffffffff

  uint64_t cr0 = X86_CR0_NE | X86_CR0_ET | X86_CR0_PE;  // turn on protection
  cr0 |= X86_CR0_PG;                                    // turn on pageing
  wvmcs(vcpu, VMCS_GUEST_CR0, cr0);
  wvmcs(vcpu, VMCS_CTRL_CR0_MASK, 0xe0000031);
  wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW, cr0);

  wvmcs(vcpu, VMCS_GUEST_CR3, tf->cr3);

  uint64_t cr4 = X86_CR4_VMXE | X86_CR4_OSFXSR | X86_CR4_OSXSAVE;
  cr4 |= X86_CR4_PAE;  // turn on 64bit paging
  wvmcs(vcpu, VMCS_GUEST_CR4, cr4);
  // make the guest unable to find it running in a virtual machine
  wvmcs(vcpu, VMCS_CTRL_CR4_MASK, X86_CR4_VMXE);
  wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0);

  uint64_t efer = 0;
  efer |= EFER_LME | EFER_LMA;  // turn on 64bit paging
  wvmcs(vcpu, VMCS_GUEST_IA32_EFER, efer);

  wreg(vcpu, HV_X86_RSI, tf->rsi);
  wreg(vcpu, HV_X86_RFLAGS, tf->rflags);

  wvmcs(vcpu, VMCS_GUEST_RIP, tf->rip);
}
#endif

void* run_vm(void* args) {
  struct vm_trapframe* tf = (struct vm_trapframe*)args;

  hv_vcpuid_t vcpu;
  GUARD(hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT), HV_SUCCESS);
  GUARD(hv_vcpu_set_space(vcpu, tf->sid), HV_SUCCESS);
#ifdef TEMP32
  vcpu_unpaged(vcpu, tf);
  void* guest_mem0_h = (void*)0x200000000ULL;
#else
  vcpu_longmode(vcpu, tf);
  void* guest_mem0_h = NULL;
#endif

  // uint64_t last_ept_gpa = 0;
  // int same_ept_violation_count = 0;
  hvdump(vcpu);
  int handled = VMEXIT_RESUME;
  while (handled != VMEXIT_STOP) {
    hv_return_t err = hv_vcpu_run(vcpu);
    if (err) {
      print_red("hv_vcpu_run: err = %llx\n", err);
      hvdump(vcpu);
      abort();
    }

    uint64_t exit_reason = rvmcs(vcpu, VMCS_RO_EXIT_REASON);
    // printf("exit_reason = %lld\n", exit_reason);
    uint64_t qual = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
    uint64_t rip = rreg(vcpu, HV_X86_RIP);
    uint64_t exit_instr_len = rvmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN);
    uint64_t cr0 = rreg(vcpu, HV_X86_CR0);

    if (exit_reason == VMX_REASON_EXC_NMI) {
      printf("VMX_REASON_EXC_NMI\n");
      uint32_t info = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO);
      uint64_t code = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_ERROR);
      dbg_print_exception_info(info, code);
      handled = VMEXIT_STOP;
    } else if (exit_reason == VMX_REASON_HLT) {
      print_red("VMX_REASON_HLT\n");
      handled = VMEXIT_STOP;
    } else if (exit_reason == VMX_REASON_IRQ) {
      uint32_t info = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO);
      uint64_t code = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_ERROR);
      // dbg_print_exception_info(info, code);

      // dbg_printf("VMX_REASON_IRQ\n");
      uint64_t cr3 = rvmcs(vcpu, VMCS_GUEST_CR3);
      uint64_t rip_h = simulate_paging(cr0, cr3, guest_mem0_h, rip);
      // printf("IRQ, rip = %llx, instruction\n", rip);
      // printf("irq instruction:\n");
      // print_payload(guest_mem0_h + rip_h, exit_instr_len + 5);
      handled = VMEXIT_RESUME;
      // hvdump(vcpu);
      // if (rip == 0xffffffff818be07eULL) {
      //   print_payload((void*)rip_h, 0x1d0 - 0x07e);
      //   handled = VMEXIT_STOP;
      // }
    } else if (exit_reason == VMX_REASON_EPT_VIOLATION) {
      // dbg_printf("VMX_REASON_EPT_VIOLATION\n");
      // dbg_print_qual(qual);
      handled = VMEXIT_RESUME;
    } else if (exit_reason == VMX_REASON_MOV_CR) {
      handled = vmm_handle_move_cr(vcpu);
    } else if (exit_reason == VMX_REASON_RDMSR) {
      handled = vmm_handle_rdmsr(vcpu);
    } else if (exit_reason == VMX_REASON_WRMSR) {
      handled = vmm_handle_wrmsr(vcpu);
    } else if (exit_reason == VMX_REASON_CPUID) {
      handled = vmm_handle_cpuid(vcpu);
    } else {
      handled = VMEXIT_STOP;
    }
    if (handled == VMEXIT_NEXT) {
      wvmcs(vcpu, VMCS_GUEST_RIP, rip + exit_instr_len);
    }
    if (handled == VMEXIT_STOP) {
      uint64_t cr3 = rvmcs(vcpu, VMCS_GUEST_CR3);
      uint64_t rip_h = simulate_paging(cr0, cr3, guest_mem0_h, rip);
      printf("instruction:\n");
      print_payload(guest_mem0_h + rip_h, exit_instr_len);
      print_payload(guest_mem0_h + rip_h + exit_instr_len, 16);

      printf("exit_reason = ");
      printf("other unhandled VMEXIT (%llu)\n", exit_reason);
      printf("qual=%llx\n", qual);
      hvdump(vcpu);
    }
  }
  return NULL;
}

void start_guest_thread(struct vm_trapframe* tf) {
  pthread_t pth;
  pthread_create(&pth, NULL, run_vm, tf);
}