#ifndef __VMEXIT_IO_H__
#define __VMEXIT_IO_H__

#include "vmm.hpp"
#include <stdint.h>
#include <Hypervisor/hv.h>

#ifdef __cplusplus
extern "C" {
#endif



enum {
  VMEXIT_QUAL_IO_BYTE_1 = 0,
  VMEXIT_QUAL_IO_BYTE_2 = 1,
  VMEXIT_QUAL_IO_BYTE_4 = 3,
};

enum {
  VMEXIT_QUAL_IO_DIR_OUT = 0,
  VMEXIT_QUAL_IO_DIR_IN = 1,
};

struct vmexit_qual_io {
  uint16_t size_access : 3;
  uint16_t direction : 1;
  uint16_t str_instr : 1;
  uint16_t REP_prefixed : 1;
  uint16_t operand : 1;
  uint16_t rsvd1 : 9;
  uint16_t port : 16;
  uint16_t rsvd2[2];
};

int vmm_handle_io(struct virtual_machine* vm, hv_vcpuid_t vcpu);
struct cf8_t {
  uint32_t offset : 8;
  uint32_t func : 3;
  uint32_t dev : 5;
  uint32_t bus : 8;
  uint32_t resv : 7;
  uint32_t enable : 1;
};

#ifdef __cplusplus
}
#endif

#endif