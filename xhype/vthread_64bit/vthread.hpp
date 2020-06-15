#ifndef __VTHREAD_HPP__
#define __VTHREAD_HPP__

#include "vmm.hpp"

struct vthread {
  struct guest_thread gth;
};

struct vthread* vthread_create(struct virtual_machine* vm, void* entry,
                               void* arg);
void vthread_join(struct vthread* vth, void** retval_loc);

#endif