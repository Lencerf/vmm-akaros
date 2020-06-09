#include "vmexit_io.h"

#include <stdio.h>

#include "utils.h"
#include "vmexit.h"

#define COUNT_OF(x) (sizeof((x)) / sizeof((x)[0]))

#ifdef PRINTD_DEBUG
#define printd(args...) printf(args)
#else
#define printd(args...) \
  {}
#endif

/* crude PCI bus. Just enough to get virtio working. I would rather not add to
 * this. */
struct pciconfig {
  uint32_t registers[256];
};

/* just index by devfn, i.e. 8 bits */
struct pciconfig pcibus[] = {
    /* linux requires that devfn 0 be a bridge.
     * 00:00.0 Host bridge: Intel Corporation 440BX/ZX/DX - 82443BX/ZX/DX Host
     * bridge (rev 01)
     */
    {
        {0x71908086, 0x02000006, 0x06000001},
    },
};

static uint32_t cf8;
static uint32_t allones = 0xffffffff;

/* Return a pointer to the 32-bit "register" in the "pcibus" give an address.
 * Use cf8.  only for readonly access.  this will fail if we ever want to do
 * writes, but we don't.
 */
void regp(uint32_t** reg) {
  *reg = &allones;
  int devfn = (cf8 >> 8) & 0xff;
  // printf("devfn %d\n", devfn);
  if (devfn < COUNT_OF(pcibus))
    *reg = &pcibus[devfn].registers[(cf8 >> 2) & 0x3f];
  // printf("-->regp *reg 0x%lx\n", **reg);
}

static void configaddr(uint32_t val) {
  printd("%s 0x%lx\n", __func__, val);
  cf8 = val;
}

static void configread32(uint32_t edx, uint64_t* reg) {
  uint32_t* r = &cf8;
  regp(&r);
  *reg = *r;
  printd("%s: 0x%lx 0x%lx, 0x%lx 0x%lx\n", __func__, cf8, edx, r, *reg);
}

static void configread16(uint32_t edx, uint64_t* reg) {
  uint64_t val;
  int which = ((edx & 2) >> 1) * 16;
  configread32(edx, &val);
  val >>= which;
  *reg = val;
  printd("%s: 0x%lx, 0x%lx 0x%lx\n", __func__, edx, val, *reg);
}

static void configread8(uint32_t edx, uint64_t* reg) {
  uint64_t val;
  int which = (edx & 3) * 8;
  configread32(edx, &val);
  val >>= which;
  *reg = val;
  printd("%s: 0x%lx, 0x%lx 0x%lx\n", __func__, edx, val, *reg);
}

static void configwrite32(uint32_t addr, uint32_t val) {
  uint32_t* r = &cf8;
  regp(&r);
  *r = val;
  printd("%s 0x%lx 0x%lx\n", __func__, addr, val);
}

UNUSED static void configwrite16(uint32_t addr, uint16_t val) {
  printd("%s 0x%lx 0x%lx\n", __func__, addr, val);
}

UNUSED static void configwrite8(uint32_t addr, uint8_t val) {
  printd("%s 0x%lx 0x%lx\n", __func__, addr, val);
}

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

// int vmm_handle_io(hv_vcpuid_t vcpu) {
//   uint64_t qual_bits = rvmcs(vcpu, VMCS_RO_EXIT_QUALIFIC);
//   struct vmexit_qual_io* qual = (struct vmexit_qual_io*)&qual_bits;
//   uint64_t rip = get_rip_h(vcpu);
//   uint64_t len = rvmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN);
//   //   printf("instrunction:\n");
//   //   print_payload((void*)rip, len);
//   //   print_qual_io(qual);
//   if (qual->direction == VMEXIT_QUAL_IO_DIR_OUT) {
//     if (qual->port == 0xcf8) {
//       if (qual->size_access == VMEXIT_QUAL_IO_BYTE_4) {  // ef
//         GUARD(*(uint8_t*)rip, 0xef);
//         cf8 = rreg(vcpu, HV_X86_RAX);
//         return VMEXIT_NEXT;
//       }
//     }
//   } else {  // VMEXIT_QUAL_IO_DIR_IN
//     if (qual->port == 0xcf8) {
//       if (qual->size_access == VMEXIT_QUAL_IO_BYTE_4) {  // ed
//         GUARD(*(uint8_t*)rip, 0xed);
//         wreg(vcpu, HV_X86_RAX, cf8);
//         return VMEXIT_NEXT;
//       }
//     } else {
//       uint64_t new_rax;
//       if (qual->size_access == VMEXIT_QUAL_IO_BYTE_4) {  // ed
//         GUARD(*(uint8_t*)rip, 0xed);
//         configread32(qual->port, &new_rax);
//       } else if (qual->size_access == VMEXIT_QUAL_IO_BYTE_2) {  // 66 ed
//         GUARD(*(uint16_t*)rip, 0xed66);
//         configread16(qual->port, &new_rax);
//       } else if (qual->size_access == VMEXIT_QUAL_IO_BYTE_1) {  // ec
//         GUARD(*(uint8_t*)rip, 0xec);
//         configread8(qual->port, &new_rax);
//       }
//       wreg(vcpu, HV_X86_RAX, new_rax);
//       return VMEXIT_NEXT;
//     }
//   }
//   return VMEXIT_STOP;
// }

/* this is very minimal. It needs to move to vmm/io.c but we don't
 * know if this minimal approach will even be workable. It only (for
 * now) handles pci config space. We'd like to hope that's all we will
 * need.
 * It would have been nice had intel encoded the IO exit info as nicely as they
 * encoded, some of the other exits.
 */
int vmm_handle_io(hv_vcpuid_t vcpu) {
  /* Get a pointer to the memory at %rip. This is quite messy and part of
   * the reason we don't want to do this at all. It sucks. Would have been
   * nice had linux had an option to ONLY do mmio config space access, but
   * no such luck.  */
  uint8_t* ip8 = NULL;
  uint16_t* ip16;
  uint8_t* ip = get_rip_h(vcpu);
  uint32_t edx = rreg(vcpu, HV_X86_RDX);
  uint32_t eax = rreg(vcpu, HV_X86_RAX);
  uint64_t new_rax = eax;

  /* Get the RIP of the io access. */
  ip8 = (void*)ip;
  ip16 = (void*)ip;
  // printf("io: ip16 %p\n", *ip16, edx);

  if (*ip8 == 0xef) {
    // vm_tf->tf_rip += 1;
    /* out at %edx */
    if (edx == 0xcf8) {
      // printf("Set cf8 ");
      configaddr(eax);
      return VMEXIT_NEXT;
    }
    if (edx == 0xcfc) {
      // printf("Set cfc ");
      configwrite32(edx, eax);
      return VMEXIT_NEXT;
    }
    /* While it is perfectly legal to do IO operations to
     * nonexistant places, we print a warning here as it
     * might also indicate a problem.  In practice these
     * types of IOs happens less frequently, and whether
     * they are bad or not is not always easy to decide.
     * Simple example: for about the first 10 years Linux
     * used to outb 0x98 to port 0x80 while idle. We
     * wouldn't want to call that an error, but that kind
     * of thing is a bad practice we ought to know about,
     * because it can cause chipset errors and result in
     * other non-obvious failures (in one case, breaking
     * BIOS reflash operations).  Plus, true story, it
     * confused people into thinking we were running
     * Windows 98, not Linux.
     */
    printd("(out rax, edx): unhandled IO address dx @%p is 0x%x\n", ip8, edx);
    return VMEXIT_NEXT;
  }
  /* TODO: sort out these various OUT operations */
  // out %al, %dx
  if (*ip8 == 0xee) {
    // vm_tf->tf_rip += 1;
    /* out al %edx */
    if (edx == 0xcfb) {  // special!
      printd("Just ignore the damned cfb write\n");
      return VMEXIT_NEXT;
    }
    if ((edx & ~3) == 0xcfc) {
      // printf("ignoring write to cfc ");
      return VMEXIT_NEXT;
    }
    if (edx == 0xcf9) {
      // on real hardware, an outb to 0xcf9 with bit 2 set is
      // about as hard a reset as you can get. It yanks the
      // reset on everything, including all the cores.  It
      // usually happens after the kernel has done lots of
      // work to carefully quiesce the machine but, once it
      // happens, game is over. Hence, an exit(0) is most
      // appropriate, since it's not an error.
      if (eax & (1 << 2)) {
        printf("outb to PCI reset port with bit 2 set: time to die\n");
        exit(0);
      }
      return VMEXIT_NEXT;
    }

    /* Another case where we print a message but it's not an error.
     * */
    printd("out al, dx: unhandled IO address dx @%p is 0x%x\n", ip8, edx);
    return VMEXIT_NEXT;
  }
  /* Silently accept OUT imm8, al */
  if (*ip8 == 0xe6) {
    // vm_tf->tf_rip += 2;
    return VMEXIT_NEXT;
  }
  /* Silently accept OUT dx, ax with opcode size modifier */
  if (*ip16 == 0xef66) {
    // vm_tf->tf_rip += 2;
    return VMEXIT_NEXT;
  }
  if (*ip8 == 0xec) {
    // vm_tf->tf_rip += 1;
    // printf("configread8 ");
    configread8(edx, &new_rax);
    wreg(vcpu, HV_X86_RAX, new_rax);
    return VMEXIT_NEXT;
  }
  if (*ip8 == 0xed) {
    // vm_tf->tf_rip += 1;
    if (edx == 0xcf8) {
      // printf("read cf8 0x%lx\n", v->regs.tf_rax);
      //   vm_tf->tf_rax = cf8;
      wreg(vcpu, HV_X86_RAX, cf8);
      return VMEXIT_NEXT;
    }
    // printf("configread32 ");
    configread32(edx, &new_rax);
    wreg(vcpu, HV_X86_RAX, new_rax);
    return VMEXIT_NEXT;
  }
  /* Detects when something is read from the PIC, so
   * a value signifying there is no PIC is given.
   */
  if (*ip16 == 0x21e4) {
    // vm_tf->tf_rip += 2;
    // vm_tf->tf_rax |= 0x00000ff;
    wreg(vcpu, HV_X86_RAX, eax | 0x00000ff);
    return VMEXIT_NEXT;
  }
  if (*ip16 == 0xed66) {
    // vm_tf->tf_rip += 2;
    // printf("configread16 ");
    configread16(edx, &new_rax);
    wreg(vcpu, HV_X86_RAX, new_rax);
    return VMEXIT_NEXT;
  }

  /* This is, so far, the only case in which we indicate
   * failure: we can't even decode the instruction. We've
   * implemented the common cases above, and recently this
   * failure has been seen only when the RIP is set to some
   * bizarre value and we start fetching instructions from
   * (e.g.) the middle of a page table. PTEs look like IO
   * instructions to the CPU.
   */
  printf("unknown IO %p %x %x\n", ip8, *ip8, *ip16);
  return VMEXIT_STOP;
}
