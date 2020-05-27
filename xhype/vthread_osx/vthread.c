#include "vthread.h"

#include <Hypervisor/hv_arch_vmx.h>
#include <Hypervisor/hv_vmx.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// #include "paging.h"
#include "utils.h"
#include "x86.h"

void hltcall(void);
#define PAGESIZE 4096ULL

mach_vm_address_t host_text_addr;
mach_vm_size_t host_text_size;

mach_vm_address_t host_data_addr;
mach_vm_size_t host_data_size;

mach_vm_address_t host_bss_addr;
mach_vm_size_t host_bss_size;

#define VM_PHYS_TEXT 0

hv_return_t vm_init(struct virtual_machine const* vm) {
  printf("pid = %d\n", getpid());
  mach_vm_address_t address = 1;
  mach_vm_size_t size;
  vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t object;
  GUARD(mach_vm_region(current_task(), &address, &size, VM_REGION_BASIC_INFO,
                       (vm_region_info_t)&info, &count, &object),
        KERN_SUCCESS);
  host_text_addr = address;
  host_text_size = size;

  address += size;
  GUARD(mach_vm_region(current_task(), &address, &size, VM_REGION_BASIC_INFO,
                       (vm_region_info_t)&info, &count, &object),
        KERN_SUCCESS);
  host_data_addr = address;
  host_data_size = size;

  address += size;
  GUARD(mach_vm_region(current_task(), &address, &size, VM_REGION_BASIC_INFO,
                       (vm_region_info_t)&info, &count, &object),
        KERN_SUCCESS);
  host_bss_addr = address;
  host_bss_size = size;

  printf("text: %llx, %lld, data: %llx, %lld, bss: %llx, %lld\n",
         host_text_addr, host_text_size, host_data_addr, host_data_size,
         host_bss_addr, host_bss_size);

  GUARD(hv_vm_create(HV_VM_DEFAULT), HV_SUCCESS);

  return 0;
}

/* desired control word constrained by hardware/hypervisor capabilities */
static uint64_t cap2ctrl(uint64_t cap, uint64_t ctrl) {
  return (ctrl | (cap & 0xffffffff)) & (cap >> 32);
}

uint64_t apos;

void* vcpu_create_run(void* vthread) {
  struct vthread* vth = vthread;
  struct virtual_machine* vm = vth->vm;

  hv_vm_space_t sid;
  GUARD(hv_vm_space_create(&sid), HV_SUCCESS);

  // memory map

  GUARD(hv_vm_map_space(sid, (uint8_t*)host_text_addr, VM_PHYS_TEXT,
                        host_text_size, HV_MEMORY_READ | HV_MEMORY_EXEC),
        HV_SUCCESS);
  GUARD(hv_vm_map_space(sid, (uint8_t*)host_data_addr,
                        VM_PHYS_TEXT + (host_data_addr - host_text_addr),
                        host_data_size, HV_MEMORY_READ | HV_MEMORY_WRITE),
        HV_SUCCESS);
  GUARD(hv_vm_map_space(sid, (uint8_t*)host_bss_addr,
                        VM_PHYS_TEXT + (host_bss_addr - host_text_addr),
                        host_bss_size, HV_MEMORY_READ | HV_MEMORY_WRITE),
        HV_SUCCESS);
  mach_vm_size_t vm_stack_size = 2 * PAGESIZE;
  uint8_t* vm_stack_h = (uint8_t*)valloc(vm_stack_size);
  GUARD(hv_vm_map_space(
            sid, vm_stack_h,
            VM_PHYS_TEXT + host_text_size + host_data_size + host_bss_size,
            vm_stack_size, HV_MEMORY_READ | HV_MEMORY_WRITE),
        HV_SUCCESS);

  // mach_vm_size_t mapped_size = host_text_size + host_data_size +
  // host_bss_size; mach_vm_address_t vm_addr = 0;
  // GUARD(mach_vm_allocate(mach_task_self(), &vm_addr,
  //                        mapped_size + vm_stack_size, VM_FLAGS_ANYWHERE),
  //       KERN_SUCCESS);
  // GUARD(mach_vm_deallocate(mach_task_self(), vm_addr, mapped_size),
  //       KERN_SUCCESS);

  // mach_vm_address_t vm_text_addr, vm_data_addr, vm_bss_addr, vm_pml4_addr,
  //     vm_stack_addr;
  // vm_text_addr = vm_addr;
  // vm_data_addr = vm_addr + host_text_size;
  // vm_bss_addr = vm_data_addr + host_data_size;
  // vm_stack_addr = vm_bss_addr + host_bss_size;
  // vm_prot_t curr_prot, max_prot;

  // GUARD(mach_vm_remap(mach_task_self(), &vm_text_addr, host_text_size, 0,
  //                     VM_FLAGS_FIXED, mach_task_self(), host_text_addr,
  //                     false, &curr_prot, &max_prot, VM_INHERIT_NONE),
  //       KERN_SUCCESS);
  // printf("text prot = %d, %d\n", curr_prot, max_prot);

  // GUARD(mach_vm_remap(mach_task_self(), &vm_data_addr, host_data_size, 0,
  //                     VM_FLAGS_FIXED, mach_task_self(), host_data_addr,
  //                     false, &curr_prot, &max_prot, VM_INHERIT_NONE),
  //       KERN_SUCCESS);
  // printf("data prot = %d, %d\n", curr_prot, max_prot);

  // GUARD(mach_vm_remap(mach_task_self(), &vm_bss_addr, host_bss_size, 0,
  //                     VM_FLAGS_FIXED, mach_task_self(), host_bss_addr, false,
  //                     &curr_prot, &max_prot, VM_INHERIT_NONE),
  //       KERN_SUCCESS);
  // printf("bss prot = %d, %d\n", curr_prot, max_prot);

  // GUARD(hv_vm_map_space(sid, (void*)vm_addr, VM_PHYS_TEXT,
  //                       mapped_size + vm_stack_size, 0),
  //       HV_SUCCESS);

  // GUARD(hv_vm_protect_space(sid, VM_PHYS_TEXT, host_text_size,
  //                           HV_MEMORY_READ | HV_MEMORY_EXEC),
  //       HV_SUCCESS);
  // GUARD(hv_vm_protect_space(sid, VM_PHYS_TEXT + (vm_data_addr -
  // vm_text_addr),
  //                           host_data_size, HV_MEMORY_READ |
  //                           HV_MEMORY_WRITE),
  //       HV_SUCCESS);
  // GUARD(hv_vm_protect_space(sid, VM_PHYS_TEXT + (vm_bss_addr - vm_text_addr),
  //                           host_bss_size, HV_MEMORY_READ | HV_MEMORY_WRITE),
  //       HV_SUCCESS);

  // GUARD(hv_vm_protect_space(sid, VM_PHYS_TEXT + (vm_stack_addr -
  // vm_text_addr),
  //                           vm_stack_size, HV_MEMORY_READ | HV_MEMORY_WRITE),
  //       HV_SUCCESS);

  hv_vcpuid_t vcpu;
  GUARD(hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT), HV_SUCCESS);
  GUARD(hv_vcpu_set_space(vcpu, sid), HV_SUCCESS);

  /* set VMCS guest state fields */
  wvmcs(vcpu, VMCS_GUEST_CS, 0);
  wvmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_CS_AR, 0xc09b);
  wvmcs(vcpu, VMCS_GUEST_CS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_DS, 0);
  wvmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_DS_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_DS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_ES, 0);
  wvmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_ES_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_ES_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_FS, 0);
  wvmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_FS_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_FS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_GS, 0);
  wvmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_GS_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_GS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_SS, 0);
  wvmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0xffffffff);
  wvmcs(vcpu, VMCS_GUEST_SS_AR, 0xc093);
  wvmcs(vcpu, VMCS_GUEST_SS_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_LDTR, 0);
  wvmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0);
  wvmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x10000);
  wvmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_TR, 0);
  wvmcs(vcpu, VMCS_GUEST_TR_LIMIT, 0);
  wvmcs(vcpu, VMCS_GUEST_TR_AR, 0x83);  // AR_TYPE_BUSY_64_TSS
  wvmcs(vcpu, VMCS_GUEST_TR_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, 0);
  wvmcs(vcpu, VMCS_GUEST_GDTR_BASE, 0);

  wvmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0);
  wvmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);

  /* get hypervisor enforced capabilities of the machine, (see Intel docs) */
  uint64_t cap_pin, cap_cpu, cap_cpu2, cap_entry, cap_exit;
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &cap_pin), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &cap_cpu), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &cap_cpu2), HV_SUCCESS);
  GUARD(hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &cap_entry), HV_SUCCESS);
  // GUARD(hv_vmx_read_capability(HV_VMX_CAP_EXIT, &cap_exit), HV_SUCCESS);
  // printf("cap_cpu2 = %llx\n", cap_cpu2);
  // print_cap(cap_pin);
  // print_cap(cap_cpu);
  // print_cap(cap_cpu2);
  // print_cap(cap_entry);
  // print_cap(cap_exit);

  /* set VMCS control fields */
  wvmcs(vcpu, VMCS_CTRL_PIN_BASED, cap2ctrl(cap_pin, 0));
  wvmcs(vcpu, VMCS_CTRL_CPU_BASED,
        cap2ctrl(cap_cpu,
                 CPU_BASED_HLT | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE));
  wvmcs(vcpu, VMCS_CTRL_CPU_BASED2, cap2ctrl(cap_cpu2, 0));
  wvmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS, cap2ctrl(cap_entry, 0));
  wvmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);

  uint64_t cr0 = X86_CR0_NE;
  cr0 |= X86_CR0_PE;
  // cr0 |= X86_CR0_PG;
  // cr0 |= X86_CR0_WP | X86_CR0_MP | X86_CR0_ET | X86_CR0_NE;
  uint64_t cr4 = X86_CR4_VMXE;
  // cr4 |= X86_CR4_PAE;
  // cr4 |= X86_CR4_OSXMMEXCPT | X86_CR4_PGE | X86_CR4_OSFXSR | X86_CR4_RDWRGSFS
  // |
  //        X86_CR4_OSXSAVE;
  uint64_t efer = 0;
  // efer |= EFER_LME | EFER_LMA;
  // efer |= EFER_SCE | EFER_NX;
  wvmcs(vcpu, VMCS_GUEST_CR0, cr0);
  // wvmcs(vcpu, VMCS_CTRL_CR0_SHADOW,
  // protected_mode | X86_CR0_WP | X86_CR0_MP | X86_CR0_ET | X86_CR0_NE);
  // wvmcs(vcpu, VMCS_CTRL_CR0_MASK, 0x60000000);

  // wvmcs(vcpu, VMCS_GUEST_CR3, vm_pml4_addr - vm_text_addr + VM_PHYS_TEXT);
  // printf("set vm cr3 to 0x%llx\n", vm_pml4_addr - vm_text_addr +
  // VM_PHYS_TEXT);

  wvmcs(vcpu, VMCS_GUEST_CR4, cr4);
  // wvmcs(vcpu, VMCS_CTRL_CR4_MASK, 0);
  // wvmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0);

  wvmcs(vcpu, VMCS_GUEST_IA32_EFER, efer);
  printf("host efer = %llx\n", rvmcs(vcpu, VMCS_HOST_IA32_EFER));

  printf("rflags = %llx\n", rvmcs(vcpu, VMCS_GUEST_RFLAGS));

  wvmcs(vcpu, VMCS_GUEST_RIP,
        (uint64_t)(vth->entry) - host_text_addr + VM_PHYS_TEXT);
  // wvmcs(vcpu, VMCS_GUEST_RFLAGS, (uint64_t)(vth->entry) -
  // host_text_addr + VM_PHYS_TEXT);
  wreg(vcpu, HV_X86_RBP, 0x10);
  wreg(vcpu, HV_X86_RFLAGS, 0x2);
  wreg(vcpu, HV_X86_RSP,
       VM_PHYS_TEXT + (host_text_size + host_data_size + host_bss_size - 1));

  printf("entry = %p\n", vth->entry);
  printf("rsp = %llx, rip = %llx\n", rreg(vcpu, HV_X86_RSP),
         rreg(vcpu, HV_X86_RIP));
  // return NULL;
  for (int i = 0; i < 6; i += 1) {
    printf("\n");
    hv_return_t err = hv_vcpu_run(vcpu);
    if (err) {
      print_red("hv_vcpu_run: err = %llx\n", err);
      abort();
    }
    uint64_t exit_reason = rvmcs(vcpu, VMCS_RO_EXIT_REASON);
    uint64_t exit_instr_len = rvmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN);
    printf("exit_reason = %llu, len=%llu\n", exit_reason, exit_instr_len);
    uint64_t bp = rreg(vcpu, HV_X86_RBP);
    uint64_t sp = rreg(vcpu, HV_X86_RSP);
    uint64_t ip = rreg(vcpu, HV_X86_RIP);
    uint64_t rax = rreg(vcpu, HV_X86_RAX);
    uint64_t rbx = rreg(vcpu, HV_X86_RBX);
    uint64_t rcx = rreg(vcpu, HV_X86_RCX);
    uint64_t qual = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
    uint64_t gla = rvmcs(vcpu, VMCS_RO_GUEST_LIN_ADDR);
    uint64_t gpa = rvmcs(vcpu, VMCS_GUEST_PHYSICAL_ADDRESS);
    uint64_t cr3 = rvmcs(vcpu, VMCS_GUEST_CR3);
    printf(
        "cr3 = %llx, bp = 0x%llx, sp=0x%llx, ip=0x%llx, rax=0x%llx, "
        "rbx=0x%llx, rcx=0x%llx\n",
        cr3, bp, sp, ip, rax, rbx, rcx);
    printf("gla=0x%llx, gpa=0x%llx\n", gla, gpa);
    printf("instruction:\n");
    // print_payload((uint8_t*)vm_text_addr + (ip - VM_PHYS_TEXT), 16);
    printf("stack:\n");
    // print_payload((uint8_t*)vm_text_addr + (sp - VM_PHYS_TEXT),
    //               mapped_size + vm_stack_size - 1 - (sp - VM_PHYS_TEXT));
    printf("gla:\n");
    // print_payload((uint8_t*)vm_text_addr + (gla - VM_PHYS_TEXT), 2);
    printf("exit_reason = ");
    if (exit_reason == VMX_REASON_HLT) {
      print_red("VMX_REASON_HLT\n");
      break;
    } else if (exit_reason == VMX_REASON_IRQ) {
      printf("VMX_REASON_IRQ\n");
    } else if (exit_reason == VMX_REASON_EPT_VIOLATION) {
      printf("VMX_REASON_EPT_VIOLATION\n");
      print_ept_vio_qualifi(qual);
      if (qual & 2) {
        apos = gla;
      }
    } else if (exit_reason == VMX_REASON_MOV_CR) {
      printf("VMX_REASON_MOV_CR\n");
    } else {
      printf("other unhandled VMEXIT (%llx)\n", exit_reason);
      break;
    }
  };
  printf("a pos = 0x%llx:\n", apos);
  // print_payload((uint8_t*)vm_text_addr + apos, 16);
  if (hv_vcpu_destroy(vcpu)) {
    abort();
  }
  // hv_vm_unmap(0, );
  return NULL;
}

struct vthread* vthread_create(struct virtual_machine const* vm, void* entry,
                               void* arg) {
  struct vthread* vth =
      (struct vthread*)malloc(sizeof(struct vthread));  // memory leak!
  vth->entry = entry;
  vth->vm = (struct virtual_machine*)vm;
  pthread_t pth;
  pthread_create(&pth, NULL, vcpu_create_run, vth);
  vth->pth = pth;
  return vth;
}

void vthread_join(struct vthread* vth, void** retval_loc) {
  pthread_join(vth->pth, retval_loc);
}