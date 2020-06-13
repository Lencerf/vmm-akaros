#include "lapic.h"
bool lapic_mmio(hv_vcpuid_t vcpu) {}

int lapic_mmio_read(uint64_t gpa, int size, uint64_t* value) { return 0; }

int lapic_mmio_write(uint64_t gpa, int size, const uint64_t* value) {
  return 0;
}