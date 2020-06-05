#include "constants.h"
#include "kernel_loader.h"
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
  GUARD(load_linux64(&vm, &vkn, kn_file, rd_file, cmd_line, 1 * GiB), 0);
  run_vm(&(vkn.tf));
}