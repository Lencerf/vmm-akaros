#include <Hypervisor/hv.h>
#include <Hypervisor/hv_arch_vmx.h>
#include <Hypervisor/hv_vmx.h>
#include <stdlib.h>

void print_green(char* msg, ...);
void print_red(char* msg, ...);
void print_payload(const void* payload, int len);
void guard(int n);

// #define GUARD(cmd, r) {
// uint64_t ret = (cmd);
// if (ret != r) {
//   print_red("%s = %lld\n", #x, ret);
//   abort();
// }
// }

#define GUARD(x, r)                      \
  {                                      \
    uint64_t ret = (uint64_t)(x);        \
    if (ret != r) {                      \
      print_red("%s = %llx\n", #x, ret); \
      exit(1);                           \
    }                                    \
  }

void print_ept_vio_qualifi(uint64_t qual);
void print_cap(uint64_t cap);
uint64_t rreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg);
void wreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg, uint64_t v);
uint64_t rvmcs(hv_vcpuid_t vcpu, uint32_t field);
void wvmcs(hv_vcpuid_t vcpu, uint32_t field, uint64_t v);
void hvdump(int vcpu);

// uint64_t cap2ctrl(uint64_t cap, uint64_t ctrl);

#define MUST1 2
#define MUST0 1
#define SUCC 0

#define WVMCS_0CAP(vcpu, cap_field, cpu_cap, value)        \
  {                                                        \
    int ret = wvmcs_0cap(vcpu, cap_field, cpu_cap, value); \
    if (ret == MUST0) {                                    \
      print_green("%s must be 0\n", #cap_field);           \
    } else if (ret == MUST0) {                             \
      print_red("%s must be 1\n", #cap_field);             \
    }                                                      \
  }

#define WVMCS_1CAP(vcpu, cap_field, cpu_cap, value)        \
  {                                                        \
    int ret = wvmcs_1cap(vcpu, cap_field, cpu_cap, value); \
    if (ret == MUST0) {                                    \
      print_red("%s must be 0\n", #cap_field);             \
    } else if (ret == MUST0) {                             \
      print_green("%s must be 1\n", #cap_field);           \
    }                                                      \
  }

int wvmcs_1cap(hv_vcpuid_t vcpu, uint32_t cap_field, uint64_t cpu_cap,
               uint64_t value);
int wvmcs_0cap(hv_vcpuid_t vcpu, uint32_t cap_field, uint64_t cpu_cap,
               uint64_t value);