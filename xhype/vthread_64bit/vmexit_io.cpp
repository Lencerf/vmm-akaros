#include "vmexit_io.h"

#include <stdio.h>

#include <unordered_map>

#include "hostbridge.hpp"
#include "lpc.hpp"
#include "pci_device.hpp"
#include "utils.h"
#include "vmexit.h"

/* VMX_REASON_IO */
void print_qual_io(void* qual_bits) {
  struct vmexit_qual_io* qual = (struct vmexit_qual_io*)qual_bits;
  printf("bytes = %d, ", qual->size_access);
  printf("in = %d, ", qual->direction);
  printf("string instr = %d, ", qual->str_instr);
  printf("rep prefixed = %d, ", qual->REP_prefixed);
  printf("operand = %d, ", qual->operand);
  printf("port = 0x%hx\n", qual->port);
}

struct cf8_t cf8;

void print_cf8() {
  fprintf(stderr, "enabled=%d, bus=%d, dev=%d, func=%d, offset=%d\n",
          cf8.enable, cf8.bus, cf8.dev, cf8.func, cf8.offset);
}

void set_all_one(uint64_t* rax, int size) {
  if (size == VMEXIT_QUAL_IO_BYTE_1) {
    *rax |= 0xffULL;
  } else if (size == VMEXIT_QUAL_IO_BYTE_2) {
    *rax |= 0xffffULL;
  } else if (size == VMEXIT_QUAL_IO_BYTE_4) {
    *rax |= 0xffffffffULL;
  } else {
    abort();
  }
}

int pci_cf8(hv_vcpuid_t vcpu, struct vmexit_qual_io* qual) {
  uint64_t rax = rreg(vcpu, HV_X86_RAX);
  if (qual->size_access != VMEXIT_QUAL_IO_BYTE_4) {
    if (qual->direction == VMEXIT_QUAL_IO_DIR_IN) {
      set_all_one(&rax, qual->size_access);
      wreg(vcpu, HV_X86_RAX, rax);
    }
  }
  if (qual->direction == VMEXIT_QUAL_IO_DIR_IN) {
    memcpy(&rax, &cf8, sizeof(cf8));
    wreg(vcpu, HV_X86_RAX, rax);
  } else {
    memcpy(&cf8, &rax, sizeof(cf8));
  }
  // print_cf8();
  return VMEXIT_NEXT;
}

std::unordered_map<uint16_t, PCIDevice*> pcd_bdf;

void add_pci_devf(uint16_t bdf, PCIDevice* devf) {
  printf("add bdf = %x\n", bdf);
  pcd_bdf[bdf] = devf;
}

int pci_cfc(hv_vcpuid_t vcpu, struct vmexit_qual_io* qual) {
  uint64_t rax = rreg(vcpu, HV_X86_RAX);
  int size = qual->size_access + 1;  // Vol.3, table 27-5
  if (cf8.enable) {
    uint16_t bdf_key;  // bus/device/function key
    memcpy(&bdf_key, (uint8_t*)&cf8 + 1, sizeof(bdf_key));
    // print_cf8();
    // if (bdf_key == 0x1f00) fprintf(stderr, "bdf_key=%x\n", bdf_key);
    if (pcd_bdf.find(bdf_key) == pcd_bdf.end()) {
      // if (bdf_key == 0x1f00) fprintf(stderr, "find no defice %x\n", bdf_key);
      if (qual->direction == VMEXIT_QUAL_IO_DIR_IN) {
        set_all_one(&rax, qual->size_access);
        wreg(vcpu, HV_X86_RAX, rax);
      }
      // out, do nothing
    } else {
      // if (bdf_key == 0x1f00) fprintf(stderr, "find defice %x\n", bdf_key);
      PCIDevice* devf = pcd_bdf[bdf_key];
      int offset = cf8.offset + (qual->port - IOPORT_PCI_CONFIG_DATA);
      if (qual->direction == VMEXIT_QUAL_IO_DIR_IN) {
        devf->read_cfg(offset, size, (uint32_t*)&rax);
        // if (bdf_key == 0x1f00) fprintf(stderr, "new rax = %llx\n", rax);
        wreg(vcpu, HV_X86_RAX, rax);
      } else {
        devf->write_cfg(offset, size, (uint32_t*)&rax);
      }
    }
  } else {
    if (qual->direction == VMEXIT_QUAL_IO_DIR_IN) {
      set_all_one(&rax, qual->size_access);
      wreg(vcpu, HV_X86_RAX, rax);
    }
  }
  return VMEXIT_NEXT;
}

typedef int (*port_handler)(hv_vcpuid_t, struct vmexit_qual_io*);

std::unordered_map<uint32_t, port_handler> handlers = {
    {IOPORT_PCI_CONFIG_ADDRESS, pci_cf8},
    {IOPORT_PCI_CONFIG_DATA, pci_cfc},
    {IOPORT_PCI_CONFIG_DATA2, pci_cfc}};

int vmm_handle_io(hv_vcpuid_t vcpu) {
  uint64_t qual_bits = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
  struct vmexit_qual_io* qual = (struct vmexit_qual_io*)&qual_bits;
  // printf("handle io at port %x, ", qual->port);
  // if (qual->direction == VMEXIT_QUAL_IO_DIR_IN) {
  //   printf("in, ");
  // } else {
  //   printf("out, ");
  // }
  if (handlers.find(qual->port) != handlers.end()) {
    int r = handlers[qual->port](vcpu, qual);
    // printf("eax = %llx\n", rreg(vcpu, HV_X86_RAX));
    return r;
  }
  // printf("unhandled\n");
  print_qual_io(qual);
  // uint64_t rip = get_rip_h(vcpu);
  // uint64_t len = rvmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN);
  // //   printf("instrunction:\n");
  // //   print_payload((void*)rip, len);
  // //   print_qual_io(qual);
  // if (qual->direction == VMEXIT_QUAL_IO_DIR_OUT) {
  //   if (qual->port == 0xcf8) {
  //     if (qual->size_access == VMEXIT_QUAL_IO_BYTE_4) {  // ef
  //       GUARD(*(uint8_t*)rip, 0xef);
  //       cf8 = rreg(vcpu, HV_X86_RAX);
  //       return VMEXIT_NEXT;
  //     }
  //   }
  // } else {  // VMEXIT_QUAL_IO_DIR_IN
  //   if (qual->port == 0xcf8) {
  //     if (qual->size_access == VMEXIT_QUAL_IO_BYTE_4) {  // ed
  //       GUARD(*(uint8_t*)rip, 0xed);
  //       wreg(vcpu, HV_X86_RAX, cf8);
  //       return VMEXIT_NEXT;
  //     }
  //   } else {
  //     uint64_t new_rax;
  //     if (qual->size_access == VMEXIT_QUAL_IO_BYTE_4) {  // ed
  //       GUARD(*(uint8_t*)rip, 0xed);
  //       configread32(qual->port, &new_rax);
  //     } else if (qual->size_access == VMEXIT_QUAL_IO_BYTE_2) {  // 66 ed
  //       GUARD(*(uint16_t*)rip, 0xed66);
  //       configread16(qual->port, &new_rax);
  //     } else if (qual->size_access == VMEXIT_QUAL_IO_BYTE_1) {  // ec
  //       GUARD(*(uint8_t*)rip, 0xec);
  //       configread8(qual->port, &new_rax);
  //     }
  //     wreg(vcpu, HV_X86_RAX, new_rax);
  //     return VMEXIT_NEXT;
  //   }
  // }
  return VMEXIT_STOP;
}

// FIX ME
// temporarily add some device here, device should be attached to virtual
// machines. we should use OOP...
void vmexit_io_init() {
  // host bridge on bus 0, dev 0, func 0
  HostBridge* hostBridge = new HostBridge();
  add_pci_devf(0, hostBridge);
  // LPC on bus 0, dev 31, func 0
  LPC* lpc = new LPC();
  add_pci_devf(31U << 3, lpc);
}