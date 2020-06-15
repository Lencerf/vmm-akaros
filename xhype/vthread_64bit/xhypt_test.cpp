#include "kernel_loader_64.hpp"
#include "vmm.hpp"
#include "vthread.hpp"

int a = 1;

void* change_a(void* args) {
  a = 132;
  return &a;
}

int main() {
  char const* kn_file = "test/vmlinuz";                       // vmlinuz
  char const* rd_file = "test/initrd.gz";                     // initrd.gz
  char const* cmd_line = "earlyprintk=serial console=ttyS0";  // auto

  vmm_init();
  struct virtual_machine vm;
  vm_init(&vm);

  struct guest_thread gth;
  load_linux64(&gth, kn_file, rd_file, cmd_line, 1 * GiB);
  guest_thread_start(&vm, &gth);

  void* vthread_ret;
  struct vthread* vth = vthread_create(&vm, (void*)change_a, NULL);

  guest_thread_join(&gth, NULL);
  vthread_join(vth, &vthread_ret);

  printf("vthread_ret =%d\n", *(int*)vthread_ret);

  printf("a=%d\n", a);
}