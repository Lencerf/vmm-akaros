#ifndef __VMEXIT_IO_H__
#define __VMEXIT_IO_H__
#include <Hypervisor/hv.h>
#include <stdint.h>

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

int vmm_handle_io(hv_vcpuid_t vcpu);

#endif