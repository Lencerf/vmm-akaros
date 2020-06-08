#ifndef __KERNEL_LOADER32_H__
#define __KERNEL_LOADER32_H__
#include <stdint.h>
#include <stdlib.h>

#include "constants.h"
#include "vmm.h"

struct vkernel {
  struct vm_trapframe tf;
  // more fields ...
};

int load_linux32(const struct virtual_machine* vm, struct vkernel* vkn,
                 char* kernel_path, char* initrd_path, char* cmd_line,
                 size_t mem_size);
#endif