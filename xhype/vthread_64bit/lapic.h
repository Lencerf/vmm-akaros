#ifndef __LAPIC_H__
#define __LAPIC_H__

#include <Hypervisor/hv.h>

#include "constants.h"

#define APIC_BASE 0xfee00000
bool lapic_mmio(hv_vcpuid_t vcpu);

bool alpic_init(hv_vcpuid_t vcpu);

int lapic_mmio_read(uint64_t gpa, int size, uint64_t* value);

int lapic_mmio_write(uint64_t gpa, int size, const uint64_t* value);

#endif