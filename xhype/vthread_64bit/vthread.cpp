#include "vthread.hpp"

#include <pthread.h>

#include "constants.h"
#include "paging.h"
#include "vmm.hpp"
#include "vthread_hlt.h"

struct vthread* vthread_create(struct virtual_machine* vm, void* entry,
                               void* arg) {
  mach_vm_address_t vthread_stack, pagetables;
  GUARD(mach_vm_allocate(mach_task_self(), &vthread_stack, VTHREAD_STACK_SIZE,
                         VM_FLAGS_ANYWHERE),
        KERN_SUCCESS);
  uint64_t* stack_top = (uint64_t*)(vthread_stack + VTHREAD_STACK_SIZE - 8);
  *stack_top = (uint64_t)vthread_hlt;

  GUARD(mach_vm_allocate(mach_task_self(), &pagetables, 2 * PAGESIZE,
                         VM_FLAGS_ANYWHERE),
        KERN_SUCCESS);
  // setup paging
  struct PML4E* pml4e = (struct PML4E*)(pagetables);
  struct PDPTE_1GB* pdpte = (struct PDPTE_1GB*)((uint8_t*)pml4e + PAGESIZE);
  pml4e[0].pres = 1;
  pml4e[0].rw = 1;
  pml4e[0].pdpt_base = ((uint64_t)pdpte) >> 12;
  for (int i = 0; i < 512; i += 1) {
    pdpte[i].pres = 1;
    pdpte[i].rw = 1;
    pdpte[i].ps = 1;
    pdpte[i].pg_base = i;
  }

  struct vthread* vth = new struct vthread;
  vth->gth.type = TYPE_VTHREAD;
  vth->gth.init_regs[HV_X86_RIP] = (uint64_t)entry;
  vth->gth.init_regs[HV_X86_RFLAGS] = 0x2;
  vth->gth.init_regs[HV_X86_RSP] = (uint64_t)stack_top;
  vth->gth.init_regs[HV_X86_CR3] = (uint64_t)pml4e;
  vth->gth.memory_maps[vthread_stack] =
      std::make_pair(vthread_stack, VTHREAD_STACK_SIZE);
  vth->gth.memory_maps[pagetables] = std::make_pair(pagetables, 2 * PAGESIZE);

  guest_thread_start(vm, &vth->gth);
  return vth;
}

void vthread_join(struct vthread* vth, void** retval_loc) {
  guest_thread_join(&vth->gth, retval_loc);
  // free memory
  for (auto pair : vth->gth.memory_maps) {
    uint64_t hva = pair.first;
    uint64_t size = pair.second.second;
    GUARD(mach_vm_deallocate(mach_task_self(), hva, size), KERN_SUCCESS);
  }
}