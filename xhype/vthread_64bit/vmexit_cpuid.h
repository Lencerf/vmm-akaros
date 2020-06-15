#ifndef __VMEXIT_CPUID_H__
#define __VMEXIT_CPUID_H__
#include <Hypervisor/hv.h>
void vmexit_cpuid_host_state_init(void);
int vmm_handle_cpuid(hv_vcpuid_t vcpu);
#endif