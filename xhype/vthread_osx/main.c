#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "vthread.h"

#define MEM_SIZE 4096

void hltcall(void);

vm_map_offset_t get_text_addr2(void) {
  mach_port_name_t task = current_task();
  vm_map_offset_t vmoffset;
  vm_map_size_t vmsize;
  uint32_t nesting_depth = 0;
  struct vm_region_submap_info_64 vbr;
  mach_msg_type_number_t vbrcount = 16;
  kern_return_t kr;

  if ((kr = mach_vm_region_recurse(task, &vmoffset, &vmsize, &nesting_depth,
                                   (vm_region_recurse_info_t)&vbr,
                                   &vbrcount)) != KERN_SUCCESS) {
    printf("FAIL");
    abort();
  }
  return vmoffset;
}

int a = 1;
extern mach_vm_address_t host_text_addr;

int add(int a, int b) { return a + b; }

void vmcall(void) {
  a = 132;
  // a = add(14, 2);
  // __asm__("movq %cr0, %rax");
  // __asm__("movq %cr3, %rbx");
  // __asm__("movq %cr4, %rcx");
  // __asm__("movq (0x6000), %rcx");
  __asm__("hlt");
}

extern uint64_t apos;

int main() {
  // mach_vm_map()
  // printf("base addr = %p\n", get_text_addr2());
  printf("vmcall = %p\n", vmcall);
  // printf("hltcall p = %p\n", hltcall);
  // uint8_t* hltcode = valloc(MEM_SIZE);  // using valloc is essential!
  // hltcode[0] = 0xf4;
  // hltcode[10] = 0xf4;
  // struct virtual_machine vm = {
  //     NULL, MEM_SIZE, HV_MEMORY_READ | HV_MEMORY_EXEC | HV_MEMORY_WRITE};
  vm_init(NULL);

  // if (vm_init(&vm)) {
  //   printf("vm_init fail\n");
  //   return -1;
  // }

  struct vthread* vth = vthread_create(NULL, vmcall, NULL);
  // // struct vthread* vth2 = vthread_create(&vm, hltcode + 10, NULL);
  vthread_join(vth, NULL);
  // vthread_join(vth2, NULL);
  // int a;
  // scanf("%d");
  // getchar();
  printf("a = %d, addr = %p, a offset = %llx\n", a, &a,
         (uint64_t)&a - host_text_addr);
  printf("a by vthread = %d\n", *(int*)(host_text_addr + apos));
  return 0;
}