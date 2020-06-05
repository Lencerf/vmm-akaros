#ifndef __KERNEL_LOADER_H__
#define __KERNEL_LOADER_H__
#include <stdint.h>
#include <stdlib.h>

#include "constants.h"
#include "vmm.h"

struct vkernel {
  struct vm_trapframe tf;
  // more fields ...
};

int load_linux64(const struct virtual_machine* vm, struct vkernel* vkn,
                 char* kernel_path, char* initrd_path, char* cmd_line,
                 size_t mem_size);
#define GDT_OFFSET (PAGE_SIZE + 4 * sizeof(uint64_t))
#define CMDLINE_OFFSET (2 * PAGE_SIZE)
#define BP_OFFSET PAGE_SIZE
#define PML4_OFFSET (3 * PAGE_SIZE)
#endif