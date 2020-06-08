#include "constants.h"
// #define TEMP32
#ifdef TEMP32
#include "kernel_loader32.h"
#else
#include "kernel_loader.h"
#endif
#include "stdio.h"
#include "utils.h"
#include "vmm.h"

int main(int argc, char **argv) {
  char *kn_file = argv[1];   // v mlinuz
  char *rd_file = argv[2];   // initrd.gz
  char *cmd_line = argv[3];  // auto

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