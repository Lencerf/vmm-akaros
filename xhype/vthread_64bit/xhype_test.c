#include "constants.h"
// #define TEMP32
#ifdef TEMP32
#include "kernel_loader32.h"
#else
#include "kernel_loader.h"
#endif
#include <assert.h>

#include "stdio.h"
#include "utils.h"
#include "vmm.h"
#include "vthread.h"

#define TESTSTR "HAPPY"

int a = 1;
int b = 2;
size_t len;

void* calc_len(void) {
  len = strlen(TESTSTR);
  // __asm__("hlt\n"); // not necessary
  return NULL;
}

void* add_a(void) {
  b += a;
  double_num(&b);
  // __asm__("hlt\n");
  return NULL;
}

uint8_t str_copy[32];

void* copy_str(void) {
  memcpy(str_copy, TESTSTR, strlen(TESTSTR) + 1);

  // __asm__("hlt\n");
  return NULL;
}

void* vmcall_printc(void) {
  char nums[] = "123456789";
  // vmcall(VTH_VMCALL_PRINTC, 'a');
  for (int i = 0; i < sizeof(nums); i += 1) {
    vmcall(VTH_VMCALL_PRINTC, nums[i]);
  }
  vmcall(VTH_VMCALL_PRINTC, '\n');
  return NULL;
}

int test_vthread() {
  vth_init();

  struct vthread* vth1 = vthread_create(add_a, NULL);
  struct vthread* vth2 = vthread_create(copy_str, NULL);
  struct vthread* vth3 = vthread_create(calc_len, NULL);

  vthread_join(vth1, NULL);
  vthread_join(vth2, NULL);
  vthread_join(vth3, NULL);

  assert(b == 6);
  assert(len == strlen(TESTSTR));
  assert(memcmp(TESTSTR, str_copy, len) == 0);
  printf("b=%d, len=%zu, str_copy=%s\n", b, len, str_copy);
  struct vthread* vth = vthread_create(vmcall_printc, NULL);
  vthread_join(vth, NULL);
  return 0;
}

int test_run_kernel() {
  char* kn_file = "test/vmlinuz";                       // vmlinuz
  char* rd_file = "test/initrd.gz";                     // initrd.gz
  char* cmd_line = "earlyprintk=serial console=ttyS0";  // auto

  vmm_init();
  struct virtual_machine vm;
  vm_init(&vm);

  struct vkernel vkn;
#ifdef TEMP32
  GUARD(load_linux32(&vm, &vkn, kn_file, rd_file, cmd_line, 1 * GiB), 0);
#else
  GUARD(load_linux64(&vm, &vkn, kn_file, rd_file, cmd_line, 1 * GiB), 0);
#endif
  run_vm(&(vkn.tf));
}

int main(int argc, char** argv) {
  test_run_kernel();
  // test_vthread();
  return 0;
}
