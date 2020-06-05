#include "vmm.h"

#include <pthread.h>
#include <stdio.h>

#include "utils.h"
#include "vmexit_qual.h"
#include "x86.h"

void vmm_init() { GUARD(hv_vm_create(HV_VM_DEFAULT), HV_SUCCESS); }

void vm_init(struct virtual_machine* vm) {
  GUARD(hv_vm_space_create(&(vm->sid)), HV_SUCCESS);
}

// Intel manuel, Volume 3, table 27-3
uint64_t vmx_get_guest_reg(int vcpu, int ident) {
  switch (ident) {
    case 0:
      return (rreg(vcpu, HV_X86_RAX));
    case 1:
      return (rreg(vcpu, HV_X86_RCX));
    case 2:
      return (rreg(vcpu, HV_X86_RDX));
    case 3:
      return (rreg(vcpu, HV_X86_RBX));
    case 4:
      return (rvmcs(vcpu, VMCS_GUEST_RSP));
    case 5:
      return (rreg(vcpu, HV_X86_RBP));
    case 6:
      return (rreg(vcpu, HV_X86_RSI));
    case 7:
      return (rreg(vcpu, HV_X86_RDI));
    case 8:
      return (rreg(vcpu, HV_X86_R8));
    case 9:
      return (rreg(vcpu, HV_X86_R9));
    case 10:
      return (rreg(vcpu, HV_X86_R10));
    case 11:
      return (rreg(vcpu, HV_X86_R11));
    case 12:
      return (rreg(vcpu, HV_X86_R12));
    case 13:
      return (rreg(vcpu, HV_X86_R13));
    case 14:
      return (rreg(vcpu, HV_X86_R14));
    case 15:
      return (rreg(vcpu, HV_X86_R15));
    default:
      abort();
  }
}

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
        cap2ctrl(cap_cpu,
                 CPU_BASED_HLT | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE));
  wvmcs(vcpu, VMCS_CTRL_CPU_BASED2, cap2ctrl(cap_cpu2, CPU_BASED2_RDTSCP));
  wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS,
        cap2ctrl(cap_entry, VMENTRY_GUEST_IA32E));  // indicate that the guest
                                                    // will be in 64bit mode

  wvmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);

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

void* run_vm(void* args) {
  struct vm_trapframe* tf = (struct vm_trapframe*)args;

  hv_vcpuid_t vcpu;
  GUARD(hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT), HV_SUCCESS);
  GUARD(hv_vcpu_set_space(vcpu, tf->sid), HV_SUCCESS);
  vcpu_longmode(vcpu, tf);
  hvdump(vcpu);
  uint64_t last_ept_gpa = 0;
  int same_ept_violation_count = 0;

  while (1) {
    hv_return_t err = hv_vcpu_run(vcpu);
    if (err) {
      print_red("hv_vcpu_run: err = %llx\n", err);
      hvdump(vcpu);
      abort();
    }

    uint64_t bp = rreg(vcpu, HV_X86_RBP);
    uint64_t sp = rreg(vcpu, HV_X86_RSP);
    uint64_t ip = rreg(vcpu, HV_X86_RIP);
    uint64_t rax = rreg(vcpu, HV_X86_RAX);
    uint64_t rbx = rreg(vcpu, HV_X86_RBX);
    uint64_t rcx = rreg(vcpu, HV_X86_RCX);
    uint64_t rdx = rreg(vcpu, HV_X86_RDX);
    uint64_t rdi = rreg(vcpu, HV_X86_RDI);
    uint64_t rsi = rreg(vcpu, HV_X86_RSI);
    uint64_t es = rreg(vcpu, HV_X86_ES);
    uint64_t gs = rreg(vcpu, HV_X86_GS);
    uint64_t gla = rvmcs(vcpu, VMCS_RO_GUEST_LIN_ADDR);
    uint64_t gpa = rvmcs(vcpu, VMCS_GUEST_PHYSICAL_ADDRESS);
    uint64_t cr3 = rvmcs(vcpu, VMCS_GUEST_CR3);
    uint64_t efer_g = rvmcs(vcpu, VMCS_GUEST_IA32_EFER);
    uint64_t exit_reason = rvmcs(vcpu, VMCS_RO_EXIT_REASON);
    if (exit_reason == VMX_REASON_EPT_VIOLATION) {
      if (gpa == last_ept_gpa) {
        same_ept_violation_count += 1;
      } else {
        last_ept_gpa = gpa;
        same_ept_violation_count = 0;
      }
      GUARD(same_ept_violation_count < 10, true);
      continue;
    }
    uint64_t exit_instr_len = rvmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN);
    uint64_t qual = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
    printf("exit_reason = %llu, len=%llu\n", exit_reason, exit_instr_len);
    printf(
        "cr3 = %llx, bp = 0x%llx, sp=0x%llx, ip=0x%llx, rax=0x%llx, "
        "rbx=0x%llx, rcx=0x%llx, efer = %llx,\n",
        cr3, bp, sp, ip, rax, rbx, rcx, efer_g);
    printf("es=0x%llx, des=0x%llx, rdi=0x%llx, rsi=0x%llx\n", es, gs, rdi, rsi);
    // if (rdi != 0) {
    //   printf("(rdi) = %x\n", *(int*)rdi);
    // }
    printf("gla=0x%llx, gpa=0x%llx\n", gla, gpa);
    // printf("instruction:\n");
    // print_payload((char*)(ip - kernel_start + kernel_start_h),
    // exit_instr_len); print_payload((void*)(ip - kernel_start + kernel_start_h
    // + exit_instr_len),
    //               16);
    // print_payload((char *)ip + exit_instr_len, 16);
    // printf("stack:\n");
    // print_payload((void*)sp, guest_stack_top - sp);

    printf("exit_reason = ");
    if (exit_reason == VMX_REASON_EXC_NMI) {
      printf("VMX_REASON_EXC_NMI\n");
      uint32_t info = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO);
      uint64_t code = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_ERROR);
      // print_bits(info, 32);
      // print_bits(code, 32);
      dbg_print_exception_info(info, code);
      // printf("code:\n");
      // print_payload((char*)ip - 64, 64);
      // printf("\n");
      // print_payload((char*)ip, 32);
      // printf("cr2=%llx\n", rreg(vcpu, HV_X86_CR2));
      break;
    } else if (exit_reason == VMX_REASON_HLT) {
      print_red("VMX_REASON_HLT\n");
      break;
    } else if (exit_reason == VMX_REASON_IRQ) {
      printf("VMX_REASON_IRQ\n");
      continue;
    } else if (exit_reason == VMX_REASON_EPT_VIOLATION) {
      printf("VMX_REASON_EPT_VIOLATION\n");
      dbg_print_qual(qual);
      //   if (gpa > kernel_start_h) {
      //     printf("accessed memroy:\n");
      //     print_payload((void *)gpa, 16);
      //   }
      continue;
    } else if (exit_reason == VMX_REASON_MOV_CR) {
      printf("VMX_REASON_MOV_CR\n");
      // the host will simulate the cr access for the host
      struct vmexit_qual_cr* qual_cr = (struct vmexit_qual_cr*)&qual;
      if (qual_cr->cr_num == 0) {
        if (qual_cr->type == VMEXIT_QUAL_CR_TYPE_MOVETO) {
          uint64_t regval = vmx_get_guest_reg(vcpu, qual_cr->g_reg);
          wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW, regval);
          wvmcs(vcpu, VMCS_GUEST_CR0, regval);
          printf("update cr0 to %llx\n", regval);
          uint64_t efer = rvmcs(vcpu, VMCS_GUEST_IA32_EFER);
          if ((regval & X86_CR0_PG) && (efer & EFER_LME)) {
            printf("turn on lma\n");
            efer |= EFER_LMA;
            wvmcs(vcpu, VMCS_GUEST_IA32_EFER, efer);
            uint64_t ctrl_entry = rvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS);
            wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS,
                  ctrl_entry | VMENTRY_GUEST_IA32E);
          } else {
          }
        } else {
          print_red("qual_cr->type = %llx\n", qual_cr->type);
          abort();
        }
      } else if (qual_cr->cr_num == 4) {
        if (qual_cr->type == VMEXIT_QUAL_CR_TYPE_MOVETO) {
          uint64_t regval = vmx_get_guest_reg(vcpu, qual_cr->g_reg);
          wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, regval);
          wvmcs(vcpu, VMCS_GUEST_CR4, regval);
          printf("update cr4 to %llx\n", regval);
        } else {
          print_red("qual_cr->type = %llx\n", qual_cr->type);
          abort();
        }
      } else if (qual_cr->cr_num == 8) {
        print_red("access cr8\n");
        abort();
      }
    } else if (exit_reason == VMX_REASON_RDMSR) {
      printf("VMX_REASON_RDMSR\n");
      if (rcx == MSR_EFER) {
        uint64_t efer_value = rvmcs(vcpu, VMCS_GUEST_IA32_EFER);
        uint32_t new_eax = (uint32_t)(efer_value & ~0Ul);
        uint32_t new_edx = (uint32_t)(efer_value >> 32);
        wreg(vcpu, HV_X86_RAX, new_eax);
        wreg(vcpu, HV_X86_RDX, new_edx);
        printf("return efer %llx to vm\n", efer_value);
      } else {
        printf("read unknow msr: %llx\n", rcx);
        break;
      }
    } else if (exit_reason == VMX_REASON_WRMSR) {
      printf("VMX_REASON_RDMSR\n");
      if (rcx == MSR_EFER) {
        uint64_t new_msr = ((uint64_t)rdx << 32) | rax;
        wvmcs(vcpu, VMCS_GUEST_IA32_EFER, new_msr);
        printf("write %llx to efer\n", new_msr);
      } else {
        printf("write unkown msr: %llx\n", rcx);
        break;
      }
    } else {
      printf("other unhandled VMEXIT (%llu)\n", exit_reason);
      break;
    }
    // advance the instrunction pointer by exit_instr_len, since the host have
    // done the instruction for the guest
    wvmcs(vcpu, VMCS_GUEST_RIP, ip + exit_instr_len);
  }
  return NULL;
}

void start_guest_thread(struct vm_trapframe* tf) {
  pthread_t pth;
  pthread_create(&pth, NULL, run_vm, tf);
}