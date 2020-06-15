## Current design

### Data structures 

`struct virtual_machine` : a vm contains the virtual hardware status and the memory map information, or EPT tables. 

`struct guest_thread` : a general guest thread can be either a virtual thread ( `struct vthread` , created by ` vthread_create() ` ) or a kernel (using ` kernel_loader_64.h ` ). A guest thread runs on a ` struct virtual_machine` . Guest threads on the same virtual machine share the same hardware resources and the same EPT table (in Apple's language, the same physical memory address space). 

Guest threads' physical address space is identical to the host's virtual address, except for for a guest kernel's lowest 100MB memory.

`struct vthread` : a vthread is the same thing as a general `struct guest_thread` . It is similar to a pthread and is created from a function call.

### Functions

`void vmm_init()` : initialize the virtual machine manager.

`void vm_init(struct virtual_machine* vm)` : initialize the virtual machine's hardware resources and memory maps

`void guest_thread_start(struct virtual_machine* vm, struct guest_thread* gth)` : run the guest `gth` on the virtual machine `vm` as the pthread of the host. 

`void guest_thread_join(struct guest_thread* gth, void** retval_loc)` :  wait the guest until it stops. If `retval_loc` is not `NULL` , the final value of the virtual CPU's register RAX is copied to `*retval_loc` .

`struct vthread* vthread_create(struct virtual_machine* vm, void* entry, void* arg)` : create a virtual thread from function `entry` and run it on `vm` .

`void vthread_join(struct vthread* vth, void** retval_loc)` : wait until the virtual thread stops.

`int load_linux64(struct guest_thread* gth, char const* kernel_path,char const* initrd_path, char const* cmd_line, uint64_t highmem_size)` : load a linux kernel and create a corresponding guest thread `gth` . This Linux guest `gth` can started by `guest_thread_start()` . 
