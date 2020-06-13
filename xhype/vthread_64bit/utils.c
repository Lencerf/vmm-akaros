

#include "utils.h"

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_arch_vmx.h>
#include <Hypervisor/hv_arch_x86.h>
#include <Hypervisor/hv_types.h>
#include <Hypervisor/hv_vmx.h>
#include <ctype.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vmcs.h"

#define DEBUG
/* desired control word constrained by hardware/hypervisor capabilities */
uint64_t cap2ctrl(uint64_t cap, uint64_t ctrl) {
  return (ctrl | (cap & 0xffffffff)) & (cap >> 32);
}

struct gva_t {
  uint64_t offset : 12;
  uint64_t table : 9;
  uint64_t dir : 9;
  uint64_t dir_p : 9;
  uint64_t pml4 : 9;
  uint64_t empty : 16;
};

// uint64_t gva2gpa(uint64_t cr3, uint64_t gva) { gva &= 0xffffffffffffULL;

//  }

void print_instr(hv_vcpuid_t vcpu, void *guest_mem) {
  uint64_t rip = rreg(vcpu, HV_X86_RIP);
  uint64_t rip_h = simulate_paging(rreg(vcpu, HV_X86_CR0),
                                   rreg(vcpu, HV_X86_CR3), guest_mem, rip);
  uint64_t len = rvmcs(vcpu, VMCS_EXIT_INSTRUCTION_LENGTH);
  printf("instructions:\n");
  print_payload((void *)(rip_h - 16), 16);
  print_payload((void *)rip_h, len);
  print_payload((void *)(rip_h + len), 16);
}

uint64_t simulate_paging(uint64_t cr0, uint64_t cr3, void *guest_mem,
                         uint64_t gva) {
  if (!(cr0 & (1UL << 31))) {
    return gva;
  }
  gva &= 0xffffffffffffULL;
  // printf("gva = %llx\n", gva);
  struct gva_t gvaddr;
  uint64_t gpa;
  memcpy(&gvaddr, &gva, sizeof(gvaddr));
  uint64_t pml4e = ((uint64_t *)(guest_mem + ((cr3 >> 12) << 12)))[gvaddr.pml4];
  if ((pml4e & 1) == 0) {
    printf("pdpt does not exit\n");
    return 0;
  } else {
    // printf("pml4e = %llx\n", pml4e);
  }
  uint64_t pdpte =
      ((uint64_t *)(guest_mem + ((pml4e >> 12) << 12)))[gvaddr.dir_p];
  if ((pdpte & 1) == 0) {
    printf("pde does not exit\n");
    return 0;
  } else {
    // printf("pdpte = %llx\n", pdpte);
  }
  if ((pdpte & (1 << 7))) {
    gpa = ((pdpte >> 30ULL) << 30ULL) + (gva & 0x3FFFFFFF);
    // printf("1GB paging, base = %llx, offset=%llx, gpa = %llx\n",
    //        (pdpte >> 30) << 30, gva & 0x3FFFFFFF, gpa);
    return gpa;
  }
  uint64_t pde = ((uint64_t *)(guest_mem + ((pdpte >> 12) << 12)))[gvaddr.dir];
  if ((pde & 1) == 0) {
    printf("pte  does not exit\n");
    return 0;
  }
  if ((pde & (1 << 7))) {
    gpa = ((pde >> 21) << 21) + (gva & 0x1fffff);
    return gpa;
  }
  uint64_t pte = ((uint64_t *)(guest_mem + ((pde >> 12) << 12)))[gvaddr.table];
  if ((pte & 1) == 0) {
    printf("page does not exit\n");
    return 0;
  }
  gpa = ((pte >> 12) << 12) + gvaddr.offset;
  return gpa;
}

uint8_t *get_rip_h(hv_vcpuid_t vcpu) {
  uint64_t rip = rreg(vcpu, HV_X86_RIP);
  uint64_t cr3 = rreg(vcpu, HV_X86_CR3);
  uint64_t cr0 = rreg(vcpu, HV_X86_CR0);
  return (uint8_t *)simulate_paging(cr0, cr3, NULL, rip);
}

// Intel manuel, Volume 3, table 27-3
uint64_t vmx_get_guest_reg(int vcpu, int ident) {
  switch (ident) {
    case 0:
      return (rreg(vcpu, HV_X86_RAX));
    case 1:
      return (rreg(vcpu, HV_X86_RCX));
    case 2:
      return (rreg(vcpu, HV_X86_RDX));
    case 3:
      return (rreg(vcpu, HV_X86_RBX));
    case 4:
      return (rvmcs(vcpu, VMCS_GUEST_RSP));
    case 5:
      return (rreg(vcpu, HV_X86_RBP));
    case 6:
      return (rreg(vcpu, HV_X86_RSI));
    case 7:
      return (rreg(vcpu, HV_X86_RDI));
    case 8:
      return (rreg(vcpu, HV_X86_R8));
    case 9:
      return (rreg(vcpu, HV_X86_R9));
    case 10:
      return (rreg(vcpu, HV_X86_R10));
    case 11:
      return (rreg(vcpu, HV_X86_R11));
    case 12:
      return (rreg(vcpu, HV_X86_R12));
    case 13:
      return (rreg(vcpu, HV_X86_R13));
    case 14:
      return (rreg(vcpu, HV_X86_R14));
    case 15:
      return (rreg(vcpu, HV_X86_R15));
    default:
      abort();
  }
}

// #define MUST1 2
// #define MUST0 1
// #define SUCC 0

// int wvmcs_1cap(hv_vcpuid_t vcpu, uint32_t cap_field, uint64_t cpu_cap,
//                uint64_t value) {
//   uint64_t can1 = cpu_cap >> 32;
//   uint64_t must1 = cpu_cap & 0xffffffffU;
//   if ((value & must1) > 0) {
//     wvmcs(vcpu, cap_field, cap2ctrl(cpu_cap, rvmcs(vcpu, cap_field)));
//     return MUST1;
//   }
//   if ((can1 & value) > 0) {
//     wvmcs(vcpu, cap_field, cap2ctrl(cpu_cap, value | rvmcs(vcpu,
//     cap_field))); return SUCC;
//   } else {
//     wvmcs(vcpu, cap_field, cap2ctrl(cpu_cap, rvmcs(vcpu, cap_field)));
//     return MUST0;
//   }
// }

// int wvmcs_0cap(hv_vcpuid_t vcpu, uint32_t cap_field, uint64_t cpu_cap,
//                uint64_t value) {
//   uint64_t can0 = cpu_cap & 0xffffffffU;
//   uint64_t must0 = cpu_cap >> 32;
//   if ((value & must0) == 0) {
//     wvmcs(vcpu, cap_field, cap2ctrl(cpu_cap, rvmcs(vcpu, cap_field)));
//     return MUST0;
//   }
//   if ((value & can0) == 0) {
//     wvmcs(vcpu, cap_field,
//           cap2ctrl(cpu_cap, (~value) & rvmcs(vcpu, cap_field)));
//     return SUCC;
//   } else {
//     wvmcs(vcpu, cap_field, cap2ctrl(cpu_cap, rvmcs(vcpu, cap_field)));
//     return MUST1;
//   }
// }

/* read GPR */
uint64_t rreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg) {
  uint64_t v;

  if (hv_vcpu_read_register(vcpu, reg, &v)) {
    abort();
  }

  return v;
}

/* write GPR */
void wreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg, uint64_t v) {
  if (hv_vcpu_write_register(vcpu, reg, v)) {
    abort();
  }
}

/* read VMCS field */
uint64_t rvmcs(hv_vcpuid_t vcpu, uint32_t field) {
  uint64_t v;

  if (hv_vmx_vcpu_read_vmcs(vcpu, field, &v)) {
    abort();
  }

  return v;
}

/* write VMCS field */
void wvmcs(hv_vcpuid_t vcpu, uint32_t field, uint64_t v) {
  if (hv_vmx_vcpu_write_vmcs(vcpu, field, v)) {
    abort();
  }
}

void dbg_hvdump(int vcpu) {
#ifdef DEBUG
  hvdump(vcpu);
#endif
}

void hvdump(int vcpu) {
  printf("VMCS_PIN_BASED_CTLS:           0x%llx\n",
         rvmcs(vcpu, VMCS_PIN_BASED_CTLS));
  printf("VMCS_PRI_PROC_BASED_CTLS:      0x%llx\n",
         rvmcs(vcpu, VMCS_PRI_PROC_BASED_CTLS));
  printf("VMCS_SEC_PROC_BASED_CTLS:      0x%llx\n",
         rvmcs(vcpu, VMCS_SEC_PROC_BASED_CTLS));
  printf("VMCS_ENTRY_CTLS:               0x%llx\n",
         rvmcs(vcpu, VMCS_ENTRY_CTLS));
  printf("VMCS_EXCEPTION_BITMAP:         0x%llx\n",
         rvmcs(vcpu, VMCS_EXCEPTION_BITMAP));
  printf("VMCS_CR0_MASK:                 0x%llx\n", rvmcs(vcpu, VMCS_CR0_MASK));
  printf("VMCS_CR0_SHADOW:               0x%llx\n",
         rvmcs(vcpu, VMCS_CR0_SHADOW));
  printf("VMCS_CR4_MASK:                 0x%llx\n", rvmcs(vcpu, VMCS_CR4_MASK));
  printf("VMCS_CR4_SHADOW:               0x%llx\n",
         rvmcs(vcpu, VMCS_CR4_SHADOW));
  printf("VMCS_GUEST_CS_SELECTOR:        0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_CS_SELECTOR));
  printf("VMCS_GUEST_CS_LIMIT:           0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_CS_LIMIT));
  printf("VMCS_GUEST_CS_AR:              0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_CS_AR));
  printf("VMCS_GUEST_CS_BASE:            0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_CS_BASE));
  printf("VMCS_GUEST_DS_SELECTOR:        0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_DS_SELECTOR));
  printf("VMCS_GUEST_DS_LIMIT:           0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_DS_LIMIT));
  printf("VMCS_GUEST_DS_AR:              0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_DS_AR));
  printf("VMCS_GUEST_DS_BASE:            0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_DS_BASE));
  printf("VMCS_GUEST_ES_SELECTOR:        0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_ES_SELECTOR));
  printf("VMCS_GUEST_ES_LIMIT:           0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_ES_LIMIT));
  printf("VMCS_GUEST_ES_AR:              0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_ES_AR));
  printf("VMCS_GUEST_ES_BASE:            0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_ES_BASE));
  printf("VMCS_GUEST_FS_SELECTOR:        0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_FS_SELECTOR));
  printf("VMCS_GUEST_FS_LIMIT:           0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_FS_LIMIT));
  printf("VMCS_GUEST_FS_AR:              0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_FS_AR));
  printf("VMCS_GUEST_FS_BASE:            0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_FS_BASE));
  printf("VMCS_GUEST_GS_SELECTOR:        0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_GS_SELECTOR));
  printf("VMCS_GUEST_GS_LIMIT:           0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_GS_LIMIT));
  printf("VMCS_GUEST_GS_AR:              0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_GS_AR));
  printf("VMCS_GUEST_GS_BASE:            0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_GS_BASE));
  printf("VMCS_GUEST_SS_SELECTOR:        0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_SS_SELECTOR));
  printf("VMCS_GUEST_SS_LIMIT:           0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_SS_LIMIT));
  printf("VMCS_GUEST_SS_AR:              0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_SS_AR));
  printf("VMCS_GUEST_SS_BASE:            0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_SS_BASE));
  printf("VMCS_GUEST_LDTR_SELECTOR:      0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_LDTR_SELECTOR));
  printf("VMCS_GUEST_LDTR_LIMIT:         0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_LDTR_LIMIT));
  printf("VMCS_GUEST_LDTR_AR:            0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_LDTR_AR));
  printf("VMCS_GUEST_LDTR_BASE:          0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_LDTR_BASE));
  printf("VMCS_GUEST_TR_SELECTOR:        0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_TR_SELECTOR));
  printf("VMCS_GUEST_TR_LIMIT:           0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_TR_LIMIT));
  printf("VMCS_GUEST_TR_AR:              0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_TR_AR));
  printf("VMCS_GUEST_TR_BASE:            0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_TR_BASE));
  printf("VMCS_GUEST_GDTR_LIMIT:         0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_GDTR_LIMIT));
  printf("VMCS_GUEST_GDTR_BASE:          0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_GDTR_BASE));
  printf("VMCS_GUEST_IDTR_LIMIT:         0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_LDTR_LIMIT));
  printf("VMCS_GUEST_IDTR_BASE:          0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_LDTR_BASE));
  printf("VMCS_GUEST_CR0:                0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_CR0));
  printf("VMCS_GUEST_CR3:                0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_CR3));
  printf("VMCS_GUEST_CR4:                0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_CR4));
  printf("VMCS_GUEST_IA32_EFER:          0x%llx\n",
         rvmcs(vcpu, VMCS_GUEST_IA32_EFER));
  printf("\n");
  printf("rip: 0x%llx rfl: 0x%llx cr2: 0x%llx\n", rreg(vcpu, HV_X86_RIP),
         rreg(vcpu, HV_X86_RFLAGS), rreg(vcpu, HV_X86_CR2));
  printf("rax: 0x%llx rbx: 0x%llx rcx: 0x%llx rdx: 0x%llx\n",
         rreg(vcpu, HV_X86_RAX), rreg(vcpu, HV_X86_RBX), rreg(vcpu, HV_X86_RCX),
         rreg(vcpu, HV_X86_RDX));
  printf("rsi: 0x%llx rdi: 0x%llx rbp: 0x%llx rsp: 0x%llx\n",
         rreg(vcpu, HV_X86_RSI), rreg(vcpu, HV_X86_RDI), rreg(vcpu, HV_X86_RBP),
         rreg(vcpu, HV_X86_RSP));
  printf("r8:  0x%llx r9:  0x%llx r10: 0x%llx r11: 0x%llx\n",
         rreg(vcpu, HV_X86_R8), rreg(vcpu, HV_X86_R9), rreg(vcpu, HV_X86_R10),
         rreg(vcpu, HV_X86_R11));
  printf("r12: 0x%llx r13: 0x%llx r14: 0x%llx r15: 0x%llx\n",
         rreg(vcpu, HV_X86_R12), rreg(vcpu, HV_X86_R12), rreg(vcpu, HV_X86_R14),
         rreg(vcpu, HV_X86_R15));
}

void dbg_print_qual(uint64_t qual) {
#ifdef DEBUG
  print_bits(qual, 17);
  //   for (int i = 12; i >= 0; i -= 1) {
  //     if (qual & (1 << i)) {
  //       printf("1");
  //     } else {
  //       printf("0");
  //     }
  //   }
  //   printf("\n");
  if (qual & (1 << 0)) {
    printf("READ, ");
  }
  if (qual & (1 << 1)) {
    printf("WRITE, ");
  }
  if (qual & (1 << 2)) {
    printf("Instruction fetch, ");
  }
  if (qual & (1 << 7)) {
    printf("VALID,");
    if (qual & (1 << 8)) {
      printf("physical,");
    } else {
      printf("to a paging structure, ");
    }
  } else {
    printf("INVALID, ");
  }
  printf("\n");
#endif
}

void dbg_printf(const char *msg, ...) {
#ifdef DEBUG
  va_list argp;

  va_start(argp, msg);
  vfprintf(stdout, msg, argp);
  va_end(argp);

#endif
}

void print_green(const char *msg, ...) {
  fprintf(stdout, "\033[32m");
  va_list argp;

  va_start(argp, msg);
  vfprintf(stdout, msg, argp);
  va_end(argp);
  fprintf(stdout, "\033[0m");
}

void print_red(const char *msg, ...) {
  fprintf(stdout, "\033[0;31m");
  va_list argp;

  va_start(argp, msg);
  vfprintf(stdout, msg, argp);
  va_end(argp);
  fprintf(stdout, "\033[0m");
}

void print_hex_ascii_line(const uint8_t *payload, int len, int offset) {
  int i;
  int gap;
  const uint8_t *ch;

  /* offset */
  printf("%05d   ", offset);

  /* hex */
  ch = payload;
  for (i = 0; i < len; i++) {
    printf("%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7) printf(" ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8) printf(" ");

  /* fill hex gap with spaces if not full line */
  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");

  /* ascii (if printable) */
  ch = payload;
  for (i = 0; i < len; i++) {
    if (isprint(*ch))
      printf("%c", *ch);
    else
      printf(".");
    ch++;
  }

  printf("\n");

  return;
}

// void print_cap(uint64_t cap) {
//   for (int i = 31; i >= 0; i -= 1) {
//     printf("%3d", i);
//   }
//   printf("\n");
//   for (int i = 63; i >= 32; i -= 1) {
//     printf("%3d", (cap & ((uint64_t)1 << i)) > 0);
//   }
//   printf("\n");
//   for (int i = 31; i >= 0; i -= 1) {
//     printf("%3d", (cap & ((uint64_t)1 << i)) > 0);
//   }
//   printf("\n\n");
// }

void dbg_print_payload(const void *payload, int len) {
#ifdef DEBUG
  print_payload(payload, len);
#endif
}

void print_payload(const void *payload, int len) {
  int len_rem = len;
  int line_width = 16; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  const uint8_t *ch = (uint8_t *)payload;

  if (len <= 0) return;

  /* data fits on one line */
  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  /* data spans multiple lines */
  for (;;) {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    print_hex_ascii_line(ch, line_len, offset);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width) {
      /* print last line and get out */
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

  return;
}

void print_bits(uint64_t num, int bits) {
  for (int i = bits - 1; i >= 0; i -= 1) {
    printf("%3d ", i);
  }
  printf("\n");
  for (int i = bits - 1; i >= 0; i -= 1) {
    printf("%3d ", (num & (1 << i)) > 0);
  }
  printf("\n");
}

void dbg_print_exception_info(uint32_t info, uint64_t code) {
#ifdef DEBUG
  uint8_t low8 = info;
  if (low8 == 2) {
    printf("NMI, ");
  } else {
    printf("vector = %d, ", low8);
  }
  uint8_t bits10_8 = (info >> 8) & 0x7;
  char *bits10_8_info[] = {"external interrupt",
                           "",
                           "non-maskabel interrupt",
                           "hardware exception",
                           "",
                           "previleged",
                           "software"};
  printf("%s, ", bits10_8_info[bits10_8]);
  if (info & (1 << 11)) {
    printf("error code = 0x%llx = %llu", code, code);
  }
  if (info & (1 << 12)) {
    printf("NMI unblocking due to IRET,");
  }
  if (info & (1U << 31)) {
    printf("valid");
  } else {
    printf("not valid");
  }
  printf("\n");
#endif
}

uint64_t vm_alloc(size_t size) {
  mach_vm_address_t addr;
  kern_return_t ret =
      mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
  return ret == KERN_SUCCESS ? addr : 0;
}

uint64_t vm_alloc_aligned(size_t size, uint64_t align) {
  mach_vm_address_t addr;
  kern_return_t ret = mach_vm_allocate(mach_task_self(), &addr, size + align,
                                       VM_FLAGS_ANYWHERE);
  if (ret == KERN_SUCCESS) {
    mach_vm_address_t addr_aligned = (addr / align + 1) * align;
    mach_vm_deallocate(mach_task_self(), addr, addr_aligned - addr);
    mach_vm_deallocate(mach_task_self(), addr_aligned + size, addr % align);
    return addr_aligned;
  } else {
    return 0;
  }
}