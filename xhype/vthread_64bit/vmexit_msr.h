#ifndef __VMEXIT_MSR_H__
#define __VMEXIT_MSR_H__
#include <Hypervisor/hv.h>
#include <stdlib.h>

void vmx_msr_init(void);
int vmm_handle_rdmsr(hv_vcpuid_t vcpu);

int vmm_handle_wrmsr(hv_vcpuid_t vcpu);

#endif