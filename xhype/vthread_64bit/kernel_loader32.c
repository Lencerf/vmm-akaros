
#include "kernel_loader32.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "linux_bootparam.h"
#include "paging.h"
#include "utils.h"

#define BASE_GDT 0x2000ull
#define BASE_ZEROPAGE 0x3000ull
#define BASE_CMDLINE 0x4000ull
#define BASE_KERNEL 0x100000ull
#define HEADER_OFFSET 0x01f1
#define HDRS 0x53726448 /* SrdH */

int load_linux32(const struct virtual_machine* vm, struct vkernel* vkn,
                 char* kernel_path, char* initrd_path, char* cmd_line,
                 size_t mem_size) {
  // verify that the kernel is relocatable
  struct setup_header* header =
      (struct setup_header*)malloc(sizeof(struct setup_header));
  FILE* kernel_fd = fopen(kernel_path, "r");
  fseek(kernel_fd, HEADER_OFFSET, SEEK_SET);
  GUARD(fread(header, sizeof(*header), 1, kernel_fd), 1);
  if (header->setup_sects == 0 || header->boot_flag != 0xaa55 ||
      header->header != HDRS || header->version < 0x020a ||
      !(header->loadflags & 1) || !header->relocatable_kernel) {
    fclose(kernel_fd);
    free(header);
    printf(
        "setup_sects = %x, boot_flag = %x, header = %x, version = %x, "
        "loadflags = %x, relocatable= %x\n",
        header->setup_sects, header->boot_flag, header->header, header->version,
        header->loadflags, header->relocatable_kernel);
    printf("kernel too old\n");
    return -1;
  }

  // uint64_t guest_mem_h = vm_alloc_aligned(mem_size,
  // header->kernel_alignment);
  uint64_t guest_mem_h = 0x200000000ULL;
  GUARD(mach_vm_allocate(mach_task_self(), &guest_mem_h, mem_size,
                         VM_FLAGS_FIXED),
        KERN_SUCCESS);
  // uint64_t guest_mem = 0;  // flat memory

  // put the boot_params at the end of guest physical memory
  struct boot_params* bp = (struct boot_params*)(guest_mem_h + BASE_ZEROPAGE);
  memcpy(&(bp->hdr), header, sizeof(*header));
  free(header);
  header = &(bp->hdr);

  struct stat kernel_fstat;
  stat(kernel_path, &kernel_fstat);
  uint64_t kernel_offset = (header->setup_sects + 1) * 512;
  uint64_t kernel_size = kernel_fstat.st_size - kernel_offset;
  uint64_t kernel_start = ALIGNUP(BASE_KERNEL, header->kernel_alignment);

  // load kernel file into guest memory
  fseek(kernel_fd, kernel_offset, SEEK_SET);
  fread((void*)(guest_mem_h + kernel_start), kernel_size, 1, kernel_fd);
  fclose(kernel_fd);

  // command line
  uint64_t cmd_line_base_h = guest_mem_h + BASE_CMDLINE;
  memcpy((void*)cmd_line_base_h, cmd_line, strlen(cmd_line) + 1);
  header->cmd_line_ptr = (uint32_t)BASE_CMDLINE;
  bp->ext_cmd_line_ptr = (BASE_CMDLINE) >> 32;

  header->hardware_subarch = 0;  // pc
  header->type_of_loader = 0xd;  // kexec

  bp->alt_mem_k = (mem_size - 0x100000) >> 10;

  // load ramdisk
  uint32_t initrd_max = bp->hdr.initrd_addr_max >= mem_size
                            ? (mem_size - 1)
                            : bp->hdr.initrd_addr_max;
  struct stat rd_fstat;
  stat(initrd_path, &rd_fstat);
  printf("initrd_max = %x, sizee = %llx\n", initrd_max, rd_fstat.st_size);
  uint64_t ramdisk_start = ALIGNDOWN(initrd_max - rd_fstat.st_size, 0x1000ull);
  printf("ramdisk_start = %llx\n", ramdisk_start);
  FILE* rd_fd = fopen(initrd_path, "r");
  GUARD(fread((void*)(guest_mem_h + ramdisk_start), rd_fstat.st_size, 1, rd_fd),
        1);
  fclose(rd_fd);

  header->ramdisk_image = (uint32_t)ramdisk_start;
  bp->ext_ramdisk_image = ramdisk_start >> 32;
  header->ramdisk_size = (uint32_t)rd_fstat.st_size;
  bp->ext_ramdisk_size = rd_fstat.st_size >> 32;

  bp->e820_map[0].addr = 0x0000000000000000;
  bp->e820_map[0].size = 0x000000000009fc00;
  bp->e820_map[0].type = 1;

  bp->e820_map[1].addr = 0x0000000000100000;
  bp->e820_map[1].size = mem_size - 0x0000000000100000;
  bp->e820_map[1].type = 1;

  bp->e820_entries = 2;

  // setup gdt
  uint64_t* gdt_entry = (uint64_t*)(guest_mem_h + BASE_GDT);
  gdt_entry[0] = 0x0000000000000000; /* null */
  gdt_entry[1] = 0x0000000000000000; /* null */
  gdt_entry[2] = 0x00cf9a000000ffff; /* code */
  gdt_entry[3] = 0x00cf92000000ffff; /* data */

  GUARD(hv_vm_map_space(vm->sid, (void*)guest_mem_h, 0, mem_size,
                        HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
        HV_SUCCESS);

  vkn->tf.gdt_base = (uint64_t)BASE_GDT;
  vkn->tf.gdt_limit = 0x1f;
  vkn->tf.rflags = 0x2;
  vkn->tf.rsi = (uint64_t)BASE_ZEROPAGE;
  vkn->tf.rbp = 0;
  vkn->tf.rbx = 0;
  vkn->tf.rdi = 0;
  vkn->tf.cr3 = 0;
  vkn->tf.rip = kernel_start;
  vkn->tf.sid = vm->sid;

  return 0;
}
