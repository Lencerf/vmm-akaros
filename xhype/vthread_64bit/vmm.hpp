#ifndef __VMM_HPP__
#define __VMM_HPP__

#include <Hypervisor/hv.h>
#include <mach/mach.h>
#include <pthread.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <utility>

#include "constants.h"
#include "utils.h"
#include "vmexit.h"
#include "x86.h"

struct virtual_machine {
  hv_vm_space_t mem_sid;  // memory space id, or EPT table id
  std::map<uint64_t, std::pair<uint64_t, uint64_t>>
      mem_map;     // hva -> (gpa, size)
  std::mutex mtx;  // memory map lock
};

#define TYPE_VTHREAD 0
#define TYPE_KERNEL 1

#define VTHREAD_STACK_SIZE (1 * MiB)

struct guest_thread {
  struct virtual_machine* vm;  // which vm this guest thread will run on

  // initial parameters to start this guest
  std::map<uint32_t, uint64_t> init_vmcs;
  std::map<hv_x86_reg_t, uint64_t> init_regs;

  int type;  // a kernel or a vthread. may be not necessary

  // for a kernel, we need its e820 table, hva -> (gpa, size)
  // for a thread, we need its stack and pagetables
  std::map<uint64_t, std::pair<uint64_t, uint64_t>> memory_maps;

  pthread_t pth;
};

void vmm_init();
void vm_init(struct virtual_machine* vm);
void guest_thread_start(struct virtual_machine* vm, struct guest_thread* gth);
void guest_thread_join(struct guest_thread* gth, void** retval_loc);
void* run_guest(void* args);

#endif