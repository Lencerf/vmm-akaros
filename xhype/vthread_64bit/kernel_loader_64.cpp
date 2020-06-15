#include "kernel_loader_64.hpp"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "linux_bootparam.h"
#include "paging.h"
#include "utils.h"

#define HEADER_OFFSET 0x01f1
#define HDRS 0x53726448 /* SrdH */
#define OFFSET_64BIT 0x200

#define GDT_OFFSET (PAGE_SIZE + 4 * sizeof(uint64_t))
#define CMDLINE_OFFSET (2 * PAGE_SIZE)
#define BP_OFFSET PAGE_SIZE
#define PML4_OFFSET (3 * PAGE_SIZE)

// fix me: check region size and file size
int load_linux64(struct guest_thread* gth, char const* kernel_path,
                 char const* initrd_path, char const* cmd_line,
                 uint64_t highmem_size) {
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

  // FIX ME
  // temporarily load the kernel to a fixed host virtual address
  // uint64_t guest_mem_h = vm_alloc_aligned(mem_size,
  // header->kernel_alignment);
  // identity map for high memory
  uint64_t guest_mem_hva = 0x200000000ULL;
  GUARD(mach_vm_allocate(mach_task_self(), &guest_mem_hva, highmem_size,
                         VM_FLAGS_FIXED),
        KERN_SUCCESS);
  uint64_t guest_mem_gpa = guest_mem_hva;
  uint64_t guest_mem_end_hva = guest_mem_hva + highmem_size;

  // put the boot_params at the end of guest physical memory
  struct boot_params* bp = (struct boot_params*)(guest_mem_end_hva - BP_OFFSET);
  memcpy(&(bp->hdr), header, sizeof(*header));
  free(header);
  header = &(bp->hdr);

  struct stat kernel_fstat;
  stat(kernel_path, &kernel_fstat);
  uint64_t kernel_offset = (header->setup_sects + 1) * 512;
  uint64_t kernel_size = kernel_fstat.st_size - kernel_offset;

  // load kernel file into guest memory
  fseek(kernel_fd, kernel_offset, SEEK_SET);
  fread((void*)guest_mem_hva, kernel_size, 1, kernel_fd);
  fclose(kernel_fd);

  // command line
  uint64_t cmd_line_base_h = guest_mem_end_hva - CMDLINE_OFFSET;
  memcpy((void*)cmd_line_base_h, cmd_line, strlen(cmd_line) + 1);
  header->cmd_line_ptr = (uint32_t)cmd_line_base_h;
  bp->ext_cmd_line_ptr = (cmd_line_base_h) >> 32;

  header->hardware_subarch = 0;  // PC
  header->type_of_loader = 0xd;  // kexec

  bp->alt_mem_k = highmem_size >> 10;  // uint: KB FIXME

  // FIX ME
  // temporary debug setup
  const uint64_t lowmem_size = 100 * MiB;
  mach_vm_address_t lowest_mem_h_fixed = 0x300000000ULL;
  GUARD(mach_vm_allocate(mach_task_self(), &lowest_mem_h_fixed, lowmem_size,
                         VM_FLAGS_FIXED),
        KERN_SUCCESS);
  uint8_t* lowest_mem_hva = (uint8_t*)lowest_mem_h_fixed;

  // load ramdisk
  uint64_t rd_base = 0x100000;
  struct stat rd_fstat;
  stat(initrd_path, &rd_fstat);
  size_t rd_region_size = ALIGNUP(rd_fstat.st_size, PAGE_SIZE);
  uint64_t rd_base_h = (uint64_t)lowest_mem_hva + rd_base;
  FILE* rd_fd = fopen(initrd_path, "r");
  GUARD(fread((void*)rd_base_h, rd_fstat.st_size, 1, rd_fd), 1);
  fclose(rd_fd);

  header->ramdisk_image = rd_base;
  bp->ext_ramdisk_image = rd_base >> 32;
  header->ramdisk_size = (uint32_t)rd_fstat.st_size;
  bp->ext_ramdisk_size = rd_fstat.st_size >> 32;

  bp->e820_map[0].addr = 0;
  bp->e820_map[0].size = 0x9fc00;
  bp->e820_map[0].type = 1;

  bp->e820_map[1].addr = rd_base;
  bp->e820_map[1].size = lowmem_size - rd_base;
  bp->e820_map[1].type = 1;

  bp->e820_map[2].addr = guest_mem_gpa;
  bp->e820_map[2].size = highmem_size;
  bp->e820_map[2].type = 1;

  bp->e820_entries = 3;

  // setup gdt
  uint64_t* gdt_entry = (uint64_t*)(guest_mem_end_hva - GDT_OFFSET);
  gdt_entry[0] = 0x0000000000000000; /* null */
  gdt_entry[1] = 0x0000000000000000; /* null */
  gdt_entry[2] = 0x00af9a000000ffff; /* code */
  gdt_entry[3] = 0x00cf92000000ffff; /* data */

  // setup paging
  struct PML4E* pml4e = (struct PML4E*)(guest_mem_end_hva - PML4_OFFSET);
  struct PDPTE_1GB* pdpte = (struct PDPTE_1GB*)((uint8_t*)pml4e - PAGE_SIZE);
  pml4e[0].pres = 1;
  pml4e[0].rw = 1;
  pml4e[0].pdpt_base = ((uint64_t)pdpte) >> 12;
  for (int i = 0; i < 512; i += 1) {
    pdpte[i].pres = 1;
    pdpte[i].rw = 1;
    pdpte[i].ps = 1;
    pdpte[i].pg_base = i;
  }

  gth->type = TYPE_KERNEL;
  gth->init_regs[HV_X86_CR3] = (uint64_t)pml4e;
  gth->init_regs[HV_X86_GDT_BASE] = (uint64_t)gdt_entry;
  gth->init_regs[HV_X86_GDT_LIMIT] = 0x1f;
  gth->init_regs[HV_X86_RFLAGS] = 0x2;
  gth->init_regs[HV_X86_RSI] = (uint64_t)bp;
  gth->init_regs[HV_X86_RIP] = guest_mem_gpa + OFFSET_64BIT;
  gth->memory_maps[guest_mem_hva] = std::make_pair(guest_mem_gpa, highmem_size);
  gth->memory_maps[(uint64_t)lowest_mem_hva] = std::make_pair(0, lowmem_size);

  return 0;
}