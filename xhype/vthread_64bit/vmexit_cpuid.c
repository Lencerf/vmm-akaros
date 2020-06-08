#include <Hypervisor/hv.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "cpuid.h"
#include "utils.h"
#include "vmexit.h"
#include "x86.h"

void cpuid_count(uint32_t ax, uint32_t cx, uint32_t* p) {
  __asm__ __volatile__("cpuid"
                       : "=a"(p[0]), "=b"(p[1]), "=c"(p[2]), "=d"(p[3])
                       : "0"(ax), "c"(cx));
}

void do_cpuid(unsigned ax, unsigned* p) {
  __asm__ __volatile__("cpuid"
                       : "=a"(p[0]), "=b"(p[1]), "=c"(p[2]), "=d"(p[3])
                       : "0"(ax));
}

#define CPUID_VM_HIGH 0x40000000
int log2(u_int x) { return (fls((int)(x << (1 - powerof2(x)))) - 1); }
/*
 * The default CPU topology is a single thread per package.
 */
static const u_int threads_per_core = 1;
static const u_int cores_per_package = 1;
static const int cpuid_leaf_b = 1;

struct xsave_limits {
  int xsave_enabled;
  uint64_t xcr0_allowed;
  uint32_t xsave_max_size;
};

static struct xsave_limits vmm_xsave_limits;

void vmm_host_state_init(void) {
  uint32_t avx1_0, regs[4];
  size_t ln;

  vmm_xsave_limits.xsave_enabled = 0;

  ln = sizeof(uint32_t);
  if (!sysctlbyname("hw.optional.avx1_0", &avx1_0, &ln, NULL, 0) && avx1_0) {
    cpuid_count(0xd, 0x0, regs);
    vmm_xsave_limits.xsave_enabled = 1;
    vmm_xsave_limits.xcr0_allowed = XFEATURE_AVX;
    vmm_xsave_limits.xsave_max_size = regs[1];
  }
}

int vmm_handle_cpuid(hv_vcpuid_t vcpu) {
  uint32_t eax = rreg(vcpu, HV_X86_RAX);
  uint32_t ebx = rreg(vcpu, HV_X86_RBX);
  uint32_t ecx = rreg(vcpu, HV_X86_RCX);
  uint32_t edx = rreg(vcpu, HV_X86_RDX);
  uint32_t regs[4] = {eax, ebx, ecx, edx};

  int level, width;
  unsigned int logical_cpus;
  uint32_t cpu_feature, cpu_high, cpu_exthigh;

  const uint32_t tsc_is_invariant = 1;
  const uint32_t smp_tsc = 1;

  do_cpuid(0, regs);
  cpu_high = regs[0];
  do_cpuid(1, regs);
  cpu_feature = regs[3];
  do_cpuid(0x80000000, regs);
  cpu_exthigh = regs[0];

  /*
   * Requests for invalid CPUID levels should map to the highest
   * available level instead.
   */
  if (cpu_exthigh != 0 && eax >= 0x80000000) {
    if (eax > cpu_exthigh) {
      eax = cpu_exthigh;
    }
  } else if (eax >= 0x40000000) {
    if (eax > CPUID_VM_HIGH) {
      eax = CPUID_VM_HIGH;
    }
  } else if (eax > cpu_high) {
    eax = cpu_high;
  }

  /*
   * In general the approach used for CPU topology is to
   * advertise a flat topology where all CPUs are packages with
   * no multi-core or SMT.
   */
  switch (eax) {
    /*
     * Pass these through to the guest
     */
    case CPUID_0000_0000:
    case CPUID_0000_0002:
    case CPUID_0000_0003:
    case CPUID_8000_0000:
    case CPUID_8000_0002:
    case CPUID_8000_0003:
    case CPUID_8000_0004:
    case CPUID_8000_0006:
      cpuid_count(eax, ecx, regs);
      break;
    case CPUID_8000_0008:
      cpuid_count(eax, ecx, regs);
      break;
    case CPUID_8000_0001:
      cpuid_count(eax, ecx, regs);

      /*
       * Hide SVM and Topology Extension features from guest.
       */
      regs[2] &= ~((unsigned)(AMDID2_SVM | AMDID2_TOPOLOGY));

      /*
       * Don't advertise extended performance counter MSRs
       * to the guest.
       */
      regs[2] &= ~((unsigned)AMDID2_PCXC);
      regs[2] &= ~((unsigned)AMDID2_PNXC);
      regs[2] &= ~((unsigned)AMDID2_PTSCEL2I);

      /*
       * Don't advertise Instruction Based Sampling feature.
       */
      regs[2] &= ~((unsigned)AMDID2_IBS);

      /* NodeID MSR not available */
      regs[2] &= ~((unsigned)AMDID2_NODE_ID);

      /* Don't advertise the OS visible workaround feature */
      regs[2] &= ~((unsigned)AMDID2_OSVW);

      /*
       * Hide rdtscp/ia32_tsc_aux until we know how
       * to deal with them.
       */
      regs[3] &= ~((unsigned)AMDID_RDTSCP);
      break;

    case CPUID_8000_0007:
      /*
       * AMD uses this leaf to advertise the processor's
       * power monitoring and RAS capabilities. These
       * features are hardware-specific and exposing
       * them to a guest doesn't make a lot of sense.
       *
       * Intel uses this leaf only to advertise the
       * "Invariant TSC" feature with all other bits
       * being reserved (set to zero).
       */
      regs[0] = 0;
      regs[1] = 0;
      regs[2] = 0;
      regs[3] = 0;

      /*
       * "Invariant TSC" can be advertised to the guest if:
       * - host TSC frequency is invariant
       * - host TSCs are synchronized across physical cpus
       *
       * XXX This still falls short because the vcpu
       * can observe the TSC moving backwards as it
       * migrates across physical cpus. But at least
       * it should discourage the guest from using the
       * TSC to keep track of time.
       */
      if (tsc_is_invariant && smp_tsc) regs[3] |= AMDPM_TSC_INVARIANT;
      break;

    case CPUID_0000_0001:
      do_cpuid(1, regs);
      /*
       * Override the APIC ID only in ebx
       */
      regs[1] &= ~((unsigned)CPUID_LOCAL_APIC_ID);
      regs[1] |= (((unsigned)vcpu) << CPUID_0000_0001_APICID_SHIFT);

      /*
       * Don't expose VMX, SpeedStep, TME or SMX capability.
       * Advertise x2APIC capability and Hypervisor guest.
       */
      regs[2] &= ~((unsigned)(CPUID2_VMX | CPUID2_EST | CPUID2_TM2));
      regs[2] &= ~((unsigned)CPUID2_SMX);

      regs[2] |= (unsigned)CPUID2_HV;

      regs[2] &= ~((unsigned)CPUID2_X2APIC);

      /*
       * Only advertise CPUID2_XSAVE in the guest if
       * the host is using XSAVE.
       */
      if (!(regs[2] & ((unsigned)CPUID2_OSXSAVE)))
        regs[2] &= ~((unsigned)CPUID2_XSAVE);

      /*
       * If CPUID2_XSAVE is being advertised and the
       * guest has set CR4_XSAVE, set
       * CPUID2_OSXSAVE.
       */
      regs[2] &= ~((unsigned)CPUID2_OSXSAVE);
      if (regs[2] & ((unsigned)CPUID2_XSAVE)) {
        uint64_t cr4 = rreg(vcpu, HV_X86_CR4);
        if (cr4 & X86_CR4_OSXSAVE) {
          regs[2] |= ((unsigned)CPUID2_OSXSAVE);
        }
      }

      /*
       * Hide monitor/mwait until we know how to deal with
       * these instructions.
       */
      regs[2] &= ~((unsigned)CPUID2_MON);

      /*
       * Hide the performance and debug features.
       */
      regs[2] &= ~((unsigned)CPUID2_PDCM);

      /*
       * No TSC deadline support in the APIC yet
       */
      regs[2] &= ~((unsigned)CPUID2_TSCDLT);

      /*
       * Hide thermal monitoring
       */
      regs[3] &= ~((unsigned)(CPUID_ACPI | CPUID_TM));

      /*
       * Hide the debug store capability.
       */
      regs[3] &= ~((unsigned)CPUID_DS);

      /*
       * Advertise the Machine Check and MTRR capability.
       *
       * Some guest OSes (e.g. Windows) will not boot if
       * these features are absent.
       */
      regs[3] |= (unsigned)(CPUID_MCA | CPUID_MCE | CPUID_MTRR);

      logical_cpus = 1 * 1;
      regs[1] &= ~((unsigned)CPUID_HTT_CORES);
      regs[1] |= (logical_cpus & 0xff) << 16;
      regs[3] |= (unsigned)CPUID_HTT;
      break;

    case CPUID_0000_0004:
      cpuid_count(eax, ecx, regs);

      if (regs[0] || regs[1] || regs[2] || regs[3]) {
        regs[0] &= 0x3ff;
        regs[0] |= (cores_per_package - 1) << 26;
        /*
         * Cache topology:
         * - L1 and L2 are shared only by the logical
         *   processors in a single core.
         * - L3 and above are shared by all logical
         *   processors in the package.
         */
        logical_cpus = threads_per_core;
        level = (regs[0] >> 5) & 0x7;
        if (level >= 3) logical_cpus *= cores_per_package;
        regs[0] |= (logical_cpus - 1) << 14;
      }
      break;

    case CPUID_0000_0007:
      regs[0] = 0;
      regs[1] = 0;
      regs[2] = 0;
      regs[3] = 0;

      /* leaf 0 */
      if (ecx == 0) {
        cpuid_count(eax, ecx, regs);

        /* Only leaf 0 is supported */
        regs[0] = 0;

        /*
         * Expose known-safe features.
         */
        regs[1] &=
            (CPUID_STDEXT_FSGSBASE | CPUID_STDEXT_BMI1 | CPUID_STDEXT_HLE |
             CPUID_STDEXT_AVX2 | CPUID_STDEXT_BMI2 | CPUID_STDEXT_ERMS |
             CPUID_STDEXT_RTM | CPUID_STDEXT_AVX512F | CPUID_STDEXT_AVX512PF |
             CPUID_STDEXT_AVX512ER | CPUID_STDEXT_AVX512CD);
        regs[2] = 0;
        regs[3] = 0;
        /* FIXME */
        // regs[1] |= CPUID_STDEXT_INVPCID;
      }
      break;

    case CPUID_0000_0006:
      regs[0] = CPUTPM1_ARAT;
      regs[1] = 0;
      regs[2] = 0;
      regs[3] = 0;
      break;

    case CPUID_0000_000A:
      /*
       * Handle the access, but report 0 for
       * all options
       */
      regs[0] = 0;
      regs[1] = 0;
      regs[2] = 0;
      regs[3] = 0;
      break;

    case CPUID_0000_000B:
      /*
       * Processor topology enumeration
       */
      logical_cpus = 0;
      width = 0;
      level = 0;
      uint32_t x2apic_id = 0;

      if (ecx == 0) {
        logical_cpus = threads_per_core;
        width = log2(logical_cpus);
        level = CPUID_TYPE_SMT;
        x2apic_id = vcpu;
      }

      if (ecx == 1) {
        logical_cpus = threads_per_core * cores_per_package;
        width = log2(logical_cpus);
        level = CPUID_TYPE_CORE;
        x2apic_id = vcpu;
      }

      if (!cpuid_leaf_b || ecx >= 2) {
        width = 0;
        logical_cpus = 0;
        level = 0;
        x2apic_id = 0;
      }

      regs[0] = width & 0x1f;
      regs[1] = logical_cpus & 0xffff;
      regs[2] = (((unsigned)level) << 8) | (ecx & 0xff);
      regs[3] = (unsigned)x2apic_id;
      break;

    case CPUID_0000_000D:;
      const struct xsave_limits* limits;
      limits = &vmm_xsave_limits;
      if (!limits->xsave_enabled) {
        regs[0] = 0;
        regs[1] = 0;
        regs[2] = 0;
        regs[3] = 0;
        break;
      }

      cpuid_count(eax, ecx, regs);
      switch (ecx) {
        case 0:
          /*
           * Only permit the guest to use bits
           * that are active in the host in
           * %xcr0.  Also, claim that the
           * maximum save area size is
           * equivalent to the host's current
           * save area size.  Since this runs
           * "inside" of vmrun(), it runs with
           * the guest's xcr0, so the current
           * save area size is correct as-is.
           */
          regs[0] &= limits->xcr0_allowed;
          regs[2] = limits->xsave_max_size;
          regs[3] &= (limits->xcr0_allowed >> 32);
          break;
        case 1:
          /* Only permit XSAVEOPT. */
          regs[0] &= CPUID_EXTSTATE_XSAVEOPT;
          regs[1] = 0;
          regs[2] = 0;
          regs[3] = 0;
          break;
        default:
          /*
           * If the leaf is for a permitted feature,
           * pass through as-is, otherwise return
           * all zeroes.
           */
          if (!(limits->xcr0_allowed & (1ul << ecx))) {
            regs[0] = 0;
            regs[1] = 0;
            regs[2] = 0;
            regs[3] = 0;
          }
          break;
      }
      break;

    case 0x40000000:

      regs[0] = CPUID_VM_HIGH;
      const char bhyve_id[12] = "bhyve bhyve ";
      bcopy(bhyve_id, &regs[1], 4);
      bcopy(bhyve_id + 4, &regs[2], 4);
      bcopy(bhyve_id + 8, &regs[3], 4);
      break;

    default:

      /*
       * The leaf value has already been clamped so
       * simply pass this through, keeping count of
       * how many unhandled leaf values have been seen.
       */
      // atomic_add_long(&bhyve_xcpuids, 1);
      cpuid_count(eax, ecx, regs);
      break;
  }

  wreg(vcpu, HV_X86_RAX, regs[0]);
  wreg(vcpu, HV_X86_RBX, regs[1]);
  wreg(vcpu, HV_X86_RCX, regs[2]);
  wreg(vcpu, HV_X86_RDX, regs[3]);

  return VMEXIT_NEXT;
}

// from Akaros
int vmm_handle_cpuid_old(hv_vcpuid_t vcpu) {
  uint32_t eax = rreg(vcpu, HV_X86_RAX);
  uint32_t ebx = rreg(vcpu, HV_X86_RBX);
  uint32_t ecx = rreg(vcpu, HV_X86_RCX);
  uint32_t edx = rreg(vcpu, HV_X86_RDX);
  uint32_t regs[4] = {eax, ebx, ecx, edx};
  if (eax == CPUID_0000_0000 || eax == CPUID_8000_0000) {
    cpuid_count(eax, ecx, regs);
  } else if (eax == CPUID_0000_0001) {
    do_cpuid(1, regs);
    /*
     * Override the APIC ID only in ebx
     */
    regs[1] &= ~((unsigned)CPUID_LOCAL_APIC_ID);
    regs[1] |= (((unsigned)vcpu) << CPUID_0000_0001_APICID_SHIFT);
    /*
     * Don't expose VMX, SpeedStep, TME or SMX capability.
     * Advertise x2APIC capability and Hypervisor guest.
     */
    regs[2] &= ~((unsigned)(CPUID2_VMX | CPUID2_EST | CPUID2_TM2));
    regs[2] &= ~((unsigned)CPUID2_SMX);

    regs[2] |= (unsigned)CPUID2_HV;
    regs[2] &= ~((unsigned)CPUID2_X2APIC);

    /*
     * Only advertise CPUID2_XSAVE in the guest if
     * the host is using XSAVE.
     */
    if (!(regs[2] & ((unsigned)CPUID2_OSXSAVE)))
      regs[2] &= ~((unsigned)CPUID2_XSAVE);

    /*
     * If CPUID2_XSAVE is being advertised and the
     * guest has set CR4_XSAVE, set
     * CPUID2_OSXSAVE.
     */
    regs[2] &= ~((unsigned)CPUID2_OSXSAVE);
    if (regs[2] & ((unsigned)CPUID2_XSAVE)) {
      uint64_t cr4 = rvmcs(vcpu, VMCS_GUEST_CR4);
      if (cr4 & X86_CR4_OSXSAVE) regs[2] |= ((unsigned)CPUID2_OSXSAVE);
    }

    /*
     * Hide monitor/mwait until we know how to deal with
     * these instructions.
     */
    regs[2] &= ~((unsigned)CPUID2_MON);

    /*
     * Hide the performance and debug features.
     */
    regs[2] &= ~((unsigned)CPUID2_PDCM);

    /*
     * No TSC deadline support in the APIC yet
     */
    regs[2] &= ~((unsigned)CPUID2_TSCDLT);

    /*
     * Hide thermal monitoring
     */
    regs[3] &= ~((unsigned)(CPUID_ACPI | CPUID_TM));

    /*
     * Hide the debug store capability.
     */
    regs[3] &= ~((unsigned)CPUID_DS);

    /*
     * Advertise the Machine Check and MTRR capability.
     *
     * Some guest OSes (e.g. Windows) will not boot if
     * these features are absent.
     */
    regs[3] |= (unsigned)(CPUID_MCA | CPUID_MCE | CPUID_MTRR);

    uint32_t logical_cpus = 1;
    regs[1] &= ~((unsigned)CPUID_HTT_CORES);
    regs[1] |= (logical_cpus & 0xff) << 16;
    regs[3] |= (unsigned)CPUID_HTT;
  } else if (eax == CPUID_8000_0001) {
    cpuid_count(eax, ecx, regs);
    /*
     * Hide SVM and Topology Extension features from guest.
     */
    regs[2] &= ~((unsigned)(AMDID2_SVM | AMDID2_TOPOLOGY));

    /*
     * Don't advertise extended performance counter MSRs
     * to the guest.
     */
    regs[2] &= ~((unsigned)AMDID2_PCXC);
    regs[2] &= ~((unsigned)AMDID2_PNXC);
    regs[2] &= ~((unsigned)AMDID2_PTSCEL2I);

    /*
     * Don't advertise Instruction Based Sampling feature.
     */
    regs[2] &= ~((unsigned)AMDID2_IBS);

    /* NodeID MSR not available */
    regs[2] &= ~((unsigned)AMDID2_NODE_ID);

    /* Don't advertise the OS visible workaround feature */
    regs[2] &= ~((unsigned)AMDID2_OSVW);

    /*
     * Hide rdtscp/ia32_tsc_aux until we know how
     * to deal with them.
     */
    regs[3] &= ~((unsigned)AMDID_RDTSCP);
  } else {
    return VMEXIT_STOP;
  }
  wreg(vcpu, HV_X86_RAX, regs[0]);
  wreg(vcpu, HV_X86_RBX, regs[1]);
  wreg(vcpu, HV_X86_RCX, regs[2]);
  wreg(vcpu, HV_X86_RDX, regs[3]);
  return VMEXIT_NEXT;
}

int vmm_handle_exception(hv_vcpuid_t vcpu) {
  uint64_t info_bits = rvmcs(vcpu, VMCS_RO_VMEXIT_IRQ_INFO);
  uint64_t qual = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
  struct vmexit_intr_info* info = (struct vmexit_intr_info*)&info_bits;
  if (info->vector == 14) {
    wreg(vcpu, HV_X86_CR2, qual);
    // VMCS_CTRL_VMENTRY_IRQ_INFO
    // VMCS_CTRL_VMENTRY_EXC_ERROR
  }
  return VMEXIT_STOP;
}
