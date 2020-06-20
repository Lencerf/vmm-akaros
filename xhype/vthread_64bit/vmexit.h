#ifndef __VMEXIT_H__
#define __VMEXIT_H__

#include <Hypervisor/hv.h>
#include <stdint.h>

#include "vmexit_cpuid.h"
#include "vmexit_io.h"
#include "vmexit_msr.h"

#define VMEXIT_STOP 0
#define VMEXIT_RESUME 1
#define VMEXIT_NEXT 2

enum {
  VMEXIT_QUAL_CR_TYPE_MOVETO = 0,
  VMEXIT_QUAL_CR_TYPE_MOVEFROM = 1,
  VMEXIT_QUAL_CR_TYPE_CLTS = 2,
  VMEXIT_QUAL_CR_TYPE_LMSW = 3
};

struct vmexit_qual_cr {
  uint64_t cr_num : 4;
  uint64_t type : 2;
  uint64_t lmsw_type : 1;
  uint64_t : 1;
  uint64_t g_reg : 4;
  uint64_t : 4;
  uint64_t lmsw_data : 16;
  uint64_t : 32;
};

struct vmexit_intr_info {
  uint32_t vector : 8;
  uint32_t type : 3;
  uint32_t code_valid : 1;
  uint32_t nmi : 1;
  uint32_t : 18;
  uint32_t valid : 1;
};

int vmm_handle_unknown(hv_vcpuid_t vcpu);

int vmm_handle_move_cr(hv_vcpuid_t vcpu);

int vmm_handle_mmio(hv_vcpuid_t vcpu);

void vmm_exit_init();

// ports
#define IOPORT_PCI_CONFIG_ADDRESS 0x0cf8
#define IOPORT_PCI_CONFIG_DATA 0x0cfc
#define IOPORT_PCI_CONFIG_DATA2 0x0cfe

typedef int (*mmio_reader)(uint64_t, int, uint64_t *);
typedef int (*mmio_writer)(uint64_t, int, const uint64_t *);

#endif