use super::X86Reg;

// VMX exit reasons
pub const VMX_REASON_EXC_NMI: u64 = 0;
pub const VMX_REASON_IRQ: u64 = 1;
pub const VMX_REASON_TRIPLE_FAULT: u64 = 2;
pub const VMX_REASON_INIT: u64 = 3;
pub const VMX_REASON_SIPI: u64 = 4;
pub const VMX_REASON_IO_SMI: u64 = 5;
pub const VMX_REASON_OTHER_SMI: u64 = 6;
pub const VMX_REASON_IRQ_WND: u64 = 7;
pub const VMX_REASON_VIRTUAL_NMI_WND: u64 = 8;
pub const VMX_REASON_TASK: u64 = 9;
pub const VMX_REASON_CPUID: u64 = 10;
pub const VMX_REASON_GETSEC: u64 = 11;
pub const VMX_REASON_HLT: u64 = 12;
pub const VMX_REASON_INVD: u64 = 13;
pub const VMX_REASON_INVLPG: u64 = 14;
pub const VMX_REASON_RDPMC: u64 = 15;
pub const VMX_REASON_RDTSC: u64 = 16;
pub const VMX_REASON_RSM: u64 = 17;
pub const VMX_REASON_VMCALL: u64 = 18;
pub const VMX_REASON_VMCLEAR: u64 = 19;
pub const VMX_REASON_VMLAUNCH: u64 = 20;
pub const VMX_REASON_VMPTRLD: u64 = 21;
pub const VMX_REASON_VMPTRST: u64 = 22;
pub const VMX_REASON_VMREAD: u64 = 23;
pub const VMX_REASON_VMRESUME: u64 = 24;
pub const VMX_REASON_VMWRITE: u64 = 25;
pub const VMX_REASON_VMOFF: u64 = 26;
pub const VMX_REASON_VMON: u64 = 27;
pub const VMX_REASON_MOV_CR: u64 = 28;
pub const VMX_REASON_MOV_DR: u64 = 29;
pub const VMX_REASON_IO: u64 = 30;
pub const VMX_REASON_RDMSR: u64 = 31;
pub const VMX_REASON_WRMSR: u64 = 32;
pub const VMX_REASON_VMENTRY_GUEST: u64 = 33;
pub const VMX_REASON_VMENTRY_MSR: u64 = 34;
pub const VMX_REASON_MWAIT: u64 = 36;
pub const VMX_REASON_MTF: u64 = 37;
pub const VMX_REASON_MONITOR: u64 = 39;
pub const VMX_REASON_PAUSE: u64 = 40;
pub const VMX_REASON_VMENTRY_MC: u64 = 41;
pub const VMX_REASON_TPR_THRESHOLD: u64 = 43;
pub const VMX_REASON_APIC_ACCESS: u64 = 44;
pub const VMX_REASON_VIRTUALIZED_EOI: u64 = 45;
pub const VMX_REASON_GDTR_IDTR: u64 = 46;
pub const VMX_REASON_LDTR_TR: u64 = 47;
pub const VMX_REASON_EPT_VIOLATION: u64 = 48;
pub const VMX_REASON_EPT_MISCONFIG: u64 = 49;
pub const VMX_REASON_EPT_INVEPT: u64 = 50;
pub const VMX_REASON_RDTSCP: u64 = 51;
pub const VMX_REASON_VMX_TIMER_EXPIRED: u64 = 52;
pub const VMX_REASON_INVVPID: u64 = 53;
pub const VMX_REASON_WBINVD: u64 = 54;
pub const VMX_REASON_XSETBV: u64 = 55;
pub const VMX_REASON_APIC_WRITE: u64 = 56;
pub const VMX_REASON_RDRAND: u64 = 57;
pub const VMX_REASON_INVPCID: u64 = 58;
pub const VMX_REASON_VMFUNC: u64 = 59;
pub const VMX_REASON_RDSEED: u64 = 61;
pub const VMX_REASON_XSAVES: u64 = 63;
pub const VMX_REASON_XRSTORS: u64 = 64;
pub const VMX_REASON_MAX: u64 = 65;

// Virtual Machine Control Structure (VMCS) field IDs

pub const VMCS_VPID: u32 = 0x00000000;
pub const VMCS_CTRL_POSTED_INT_N_VECTOR: u32 = 0x00000002;
pub const VMCS_CTRL_EPTP_INDEX: u32 = 0x00000004;
pub const VMCS_GUEST_ES: u32 = 0x00000800;
pub const VMCS_GUEST_CS: u32 = 0x00000802;
pub const VMCS_GUEST_SS: u32 = 0x00000804;
pub const VMCS_GUEST_DS: u32 = 0x00000806;
pub const VMCS_GUEST_FS: u32 = 0x00000808;
pub const VMCS_GUEST_GS: u32 = 0x0000080a;
pub const VMCS_GUEST_LDTR: u32 = 0x0000080c;
pub const VMCS_GUEST_TR: u32 = 0x0000080e;
pub const VMCS_GUEST_INT_STATUS: u32 = 0x00000810;
pub const VMCS_HOST_ES: u32 = 0x00000c00;
pub const VMCS_HOST_CS: u32 = 0x00000c02;
pub const VMCS_HOST_SS: u32 = 0x00000c04;
pub const VMCS_HOST_DS: u32 = 0x00000c06;
pub const VMCS_HOST_FS: u32 = 0x00000c08;
pub const VMCS_HOST_GS: u32 = 0x00000c0a;
pub const VMCS_HOST_TR: u32 = 0x00000c0c;
pub const VMCS_CTRL_IO_BITMAP_A: u32 = 0x00002000;
pub const VMCS_CTRL_IO_BITMAP_B: u32 = 0x00002002;
pub const VMCS_CTRL_MSR_BITMAPS: u32 = 0x00002004;
pub const VMCS_CTRL_VMEXIT_MSR_STORE_ADDR: u32 = 0x00002006;
pub const VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR: u32 = 0x00002008;
pub const VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR: u32 = 0x0000200a;
pub const VMCS_CTRL_EXECUTIVE_VMCS_PTR: u32 = 0x0000200c;
pub const VMCS_CTRL_TSC_OFFSET: u32 = 0x00002010;
pub const VMCS_CTRL_VIRTUAL_APIC: u32 = 0x00002012;
pub const VMCS_CTRL_APIC_ACCESS: u32 = 0x00002014;
pub const VMCS_CTRL_POSTED_INT_DESC_ADDR: u32 = 0x00002016;
pub const VMCS_CTRL_VMFUNC_CTRL: u32 = 0x00002018;
pub const VMCS_CTRL_EPTP: u32 = 0x0000201a;
pub const VMCS_CTRL_EOI_EXIT_BITMAP_0: u32 = 0x0000201c;
pub const VMCS_CTRL_EOI_EXIT_BITMAP_1: u32 = 0x0000201e;
pub const VMCS_CTRL_EOI_EXIT_BITMAP_2: u32 = 0x00002020;
pub const VMCS_CTRL_EOI_EXIT_BITMAP_3: u32 = 0x00002022;
pub const VMCS_CTRL_EPTP_LIST_ADDR: u32 = 0x00002024;
pub const VMCS_CTRL_VMREAD_BITMAP_ADDR: u32 = 0x00002026;
pub const VMCS_CTRL_VMWRITE_BITMAP_ADDR: u32 = 0x00002028;
pub const VMCS_CTRL_VIRT_EXC_INFO_ADDR: u32 = 0x0000202a;
pub const VMCS_CTRL_XSS_EXITING_BITMAP: u32 = 0x0000202c;
pub const VMCS_GUEST_PHYSICAL_ADDRESS: u32 = 0x00002400;
pub const VMCS_GUEST_LINK_POINTER: u32 = 0x00002800;
pub const VMCS_GUEST_IA32_DEBUGCTL: u32 = 0x00002802;
pub const VMCS_GUEST_IA32_PAT: u32 = 0x00002804;
pub const VMCS_GUEST_IA32_EFER: u32 = 0x00002806;
pub const VMCS_GUEST_IA32_PERF_GLOBAL_CTRL: u32 = 0x00002808;
pub const VMCS_GUEST_PDPTE0: u32 = 0x0000280a;
pub const VMCS_GUEST_PDPTE1: u32 = 0x0000280c;
pub const VMCS_GUEST_PDPTE2: u32 = 0x0000280e;
pub const VMCS_GUEST_PDPTE3: u32 = 0x00002810;
pub const VMCS_HOST_IA32_PAT: u32 = 0x00002c00;
pub const VMCS_HOST_IA32_EFER: u32 = 0x00002c02;
pub const VMCS_HOST_IA32_PERF_GLOBAL_CTRL: u32 = 0x00002c04;
pub const VMCS_CTRL_PIN_BASED: u32 = 0x00004000;
pub const VMCS_CTRL_CPU_BASED: u32 = 0x00004002;
pub const VMCS_CTRL_EXC_BITMAP: u32 = 0x00004004;
pub const VMCS_CTRL_PF_ERROR_MASK: u32 = 0x00004006;
pub const VMCS_CTRL_PF_ERROR_MATCH: u32 = 0x00004008;
pub const VMCS_CTRL_CR3_COUNT: u32 = 0x0000400a;
pub const VMCS_CTRL_VMEXIT_CONTROLS: u32 = 0x0000400c;
pub const VMCS_CTRL_VMEXIT_MSR_STORE_COUNT: u32 = 0x0000400e;
pub const VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT: u32 = 0x00004010;
pub const VMCS_CTRL_VMENTRY_CONTROLS: u32 = 0x00004012;
pub const VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT: u32 = 0x00004014;
pub const VMCS_CTRL_VMENTRY_IRQ_INFO: u32 = 0x00004016;
pub const VMCS_CTRL_VMENTRY_EXC_ERROR: u32 = 0x00004018;
pub const VMCS_CTRL_VMENTRY_INSTR_LEN: u32 = 0x0000401a;
pub const VMCS_CTRL_TPR_THRESHOLD: u32 = 0x0000401c;
pub const VMCS_CTRL_CPU_BASED2: u32 = 0x0000401e;
pub const VMCS_CTRL_PLE_GAP: u32 = 0x00004020;
pub const VMCS_CTRL_PLE_WINDOW: u32 = 0x00004022;
pub const VMCS_RO_INSTR_ERROR: u32 = 0x00004400;
pub const VMCS_RO_EXIT_REASON: u32 = 0x00004402;
pub const VMCS_RO_VMEXIT_IRQ_INFO: u32 = 0x00004404;
pub const VMCS_RO_VMEXIT_IRQ_ERROR: u32 = 0x00004406;
pub const VMCS_RO_IDT_VECTOR_INFO: u32 = 0x00004408;
pub const VMCS_RO_IDT_VECTOR_ERROR: u32 = 0x0000440a;
pub const VMCS_RO_VMEXIT_INSTR_LEN: u32 = 0x0000440c;
pub const VMCS_RO_VMX_INSTR_INFO: u32 = 0x0000440e;
pub const VMCS_GUEST_ES_LIMIT: u32 = 0x00004800;
pub const VMCS_GUEST_CS_LIMIT: u32 = 0x00004802;
pub const VMCS_GUEST_SS_LIMIT: u32 = 0x00004804;
pub const VMCS_GUEST_DS_LIMIT: u32 = 0x00004806;
pub const VMCS_GUEST_FS_LIMIT: u32 = 0x00004808;
pub const VMCS_GUEST_GS_LIMIT: u32 = 0x0000480a;
pub const VMCS_GUEST_LDTR_LIMIT: u32 = 0x0000480c;
pub const VMCS_GUEST_TR_LIMIT: u32 = 0x0000480e;
pub const VMCS_GUEST_GDTR_LIMIT: u32 = 0x00004810;
pub const VMCS_GUEST_IDTR_LIMIT: u32 = 0x00004812;
pub const VMCS_GUEST_ES_AR: u32 = 0x00004814;
pub const VMCS_GUEST_CS_AR: u32 = 0x00004816;
pub const VMCS_GUEST_SS_AR: u32 = 0x00004818;
pub const VMCS_GUEST_DS_AR: u32 = 0x0000481a;
pub const VMCS_GUEST_FS_AR: u32 = 0x0000481c;
pub const VMCS_GUEST_GS_AR: u32 = 0x0000481e;
pub const VMCS_GUEST_LDTR_AR: u32 = 0x00004820;
pub const VMCS_GUEST_TR_AR: u32 = 0x00004822;
pub const VMCS_GUEST_IGNORE_IRQ: u32 = 0x00004824;
pub const VMCS_GUEST_ACTIVITY_STATE: u32 = 0x00004826;
pub const VMCS_GUEST_SMBASE: u32 = 0x00004828;
pub const VMCS_GUEST_IA32_SYSENTER_CS: u32 = 0x0000482a;
pub const VMCS_GUEST_VMX_TIMER_VALUE: u32 = 0x0000482e;
pub const VMCS_HOST_IA32_SYSENTER_CS: u32 = 0x00004c00;
pub const VMCS_CTRL_CR0_MASK: u32 = 0x00006000;
pub const VMCS_CTRL_CR4_MASK: u32 = 0x00006002;
pub const VMCS_CTRL_CR0_SHADOW: u32 = 0x00006004;
pub const VMCS_CTRL_CR4_SHADOW: u32 = 0x00006006;
pub const VMCS_CTRL_CR3_VALUE0: u32 = 0x00006008;
pub const VMCS_CTRL_CR3_VALUE1: u32 = 0x0000600a;
pub const VMCS_CTRL_CR3_VALUE2: u32 = 0x0000600c;
pub const VMCS_CTRL_CR3_VALUE3: u32 = 0x0000600e;
pub const VMCS_RO_EXIT_QUALIFIC: u32 = 0x00006400;
pub const VMCS_RO_IO_RCX: u32 = 0x00006402;
pub const VMCS_RO_IO_RSI: u32 = 0x00006404;
pub const VMCS_RO_IO_RDI: u32 = 0x00006406;
pub const VMCS_RO_IO_RIP: u32 = 0x00006408;
pub const VMCS_RO_GUEST_LIN_ADDR: u32 = 0x0000640a;
pub const VMCS_GUEST_CR0: u32 = 0x00006800;
pub const VMCS_GUEST_CR3: u32 = 0x00006802;
pub const VMCS_GUEST_CR4: u32 = 0x00006804;
pub const VMCS_GUEST_ES_BASE: u32 = 0x00006806;
pub const VMCS_GUEST_CS_BASE: u32 = 0x00006808;
pub const VMCS_GUEST_SS_BASE: u32 = 0x0000680a;
pub const VMCS_GUEST_DS_BASE: u32 = 0x0000680c;
pub const VMCS_GUEST_FS_BASE: u32 = 0x0000680e;
pub const VMCS_GUEST_GS_BASE: u32 = 0x00006810;
pub const VMCS_GUEST_LDTR_BASE: u32 = 0x00006812;
pub const VMCS_GUEST_TR_BASE: u32 = 0x00006814;
pub const VMCS_GUEST_GDTR_BASE: u32 = 0x00006816;
pub const VMCS_GUEST_IDTR_BASE: u32 = 0x00006818;
pub const VMCS_GUEST_DR7: u32 = 0x0000681a;
pub const VMCS_GUEST_RSP: u32 = 0x0000681c;
pub const VMCS_GUEST_RIP: u32 = 0x0000681e;
pub const VMCS_GUEST_RFLAGS: u32 = 0x00006820;
pub const VMCS_GUEST_DEBUG_EXC: u32 = 0x00006822;
pub const VMCS_GUEST_SYSENTER_ESP: u32 = 0x00006824;
pub const VMCS_GUEST_SYSENTER_EIP: u32 = 0x00006826;
pub const VMCS_HOST_CR0: u32 = 0x00006c00;
pub const VMCS_HOST_CR3: u32 = 0x00006c02;
pub const VMCS_HOST_CR4: u32 = 0x00006c04;
pub const VMCS_HOST_FS_BASE: u32 = 0x00006c06;
pub const VMCS_HOST_GS_BASE: u32 = 0x00006c08;
pub const VMCS_HOST_TR_BASE: u32 = 0x00006c0a;
pub const VMCS_HOST_GDTR_BASE: u32 = 0x00006c0c;
pub const VMCS_HOST_IDTR_BASE: u32 = 0x00006c0e;
pub const VMCS_HOST_IA32_SYSENTER_ESP: u32 = 0x00006c10;
pub const VMCS_HOST_IA32_SYSENTER_EIP: u32 = 0x00006c12;
pub const VMCS_HOST_RSP: u32 = 0x00006c14;
pub const VMCS_HOST_RIP: u32 = 0x00006c16;
pub const VMCS_MAX: u32 = 0x00006c18;

// VMX capability field values

pub const PIN_BASED_INTR: u64 = 1 << 0;
pub const PIN_BASED_NMI: u64 = 1 << 3;
pub const PIN_BASED_VIRTUAL_NMI: u64 = 1 << 5;
pub const PIN_BASED_PREEMPTION_TIMER: u64 = 1 << 6;
pub const PIN_BASED_POSTED_INTR: u64 = 1 << 7;

pub const CPU_BASED_IRQ_WND: u64 = 1 << 2;
pub const CPU_BASED_TSC_OFFSET: u64 = 1 << 3;
pub const CPU_BASED_HLT: u64 = 1 << 7;
pub const CPU_BASED_INVLPG: u64 = 1 << 9;
pub const CPU_BASED_MWAIT: u64 = 1 << 10;
pub const CPU_BASED_RDPMC: u64 = 1 << 11;
pub const CPU_BASED_RDTSC: u64 = 1 << 12;
pub const CPU_BASED_CR3_LOAD: u64 = 1 << 15;
pub const CPU_BASED_CR3_STORE: u64 = 1 << 16;
pub const CPU_BASED_CR8_LOAD: u64 = 1 << 19;
pub const CPU_BASED_CR8_STORE: u64 = 1 << 20;
pub const CPU_BASED_TPR_SHADOW: u64 = 1 << 21;
pub const CPU_BASED_VIRTUAL_NMI_WND: u64 = 1 << 22;
pub const CPU_BASED_MOV_DR: u64 = 1 << 23;
pub const CPU_BASED_UNCOND_IO: u64 = 1 << 24;
pub const CPU_BASED_IO_BITMAPS: u64 = 1 << 25;
pub const CPU_BASED_MTF: u64 = 1 << 27;
pub const CPU_BASED_MSR_BITMAPS: u64 = 1 << 28;
pub const CPU_BASED_MONITOR: u64 = 1 << 29;
pub const CPU_BASED_PAUSE: u64 = 1 << 30;
pub const CPU_BASED_SECONDARY_CTLS: u64 = 1 << 31;

pub const CPU_BASED2_VIRTUAL_APIC: u64 = 1 << 0;
pub const CPU_BASED2_EPT: u64 = 1 << 1;
pub const CPU_BASED2_DESC_TABLE: u64 = 1 << 2;
pub const CPU_BASED2_RDTSCP: u64 = 1 << 3;
pub const CPU_BASED2_X2APIC: u64 = 1 << 4;
pub const CPU_BASED2_VPID: u64 = 1 << 5;
pub const CPU_BASED2_WBINVD: u64 = 1 << 6;
pub const CPU_BASED2_UNRESTRICTED: u64 = 1 << 7;
pub const CPU_BASED2_APIC_REG_VIRT: u64 = 1 << 8;
pub const CPU_BASED2_VIRT_INTR_DELIVERY: u64 = 1 << 9;
pub const CPU_BASED2_PAUSE_LOOP: u64 = 1 << 10;
pub const CPU_BASED2_RDRAND: u64 = 1 << 11;
pub const CPU_BASED2_INVPCID: u64 = 1 << 12;
pub const CPU_BASED2_VMFUNC: u64 = 1 << 13;
pub const CPU_BASED2_VMCS_SHADOW: u64 = 1 << 14;
pub const CPU_BASED2_RDSEED: u64 = 1 << 16;
pub const CPU_BASED2_EPT_VE: u64 = 1 << 18;
pub const CPU_BASED2_XSAVES_XRSTORS: u64 = 1 << 20;

pub const VMX_EPT_VPID_SUPPORT_AD: u64 = 1 << 21;
pub const VMX_EPT_VPID_SUPPORT_EXONLY: u64 = 1 << 0;

pub const VMEXIT_SAVE_DBG_CONTROLS: u64 = 1 << 2;
pub const VMEXIT_HOST_IA32E: u64 = 1 << 9;
pub const VMEXIT_LOAD_IA32_PERF_GLOBAL_CTRL: u64 = 1 << 12;
pub const VMEXIT_ACK_INTR: u64 = 1 << 15;
pub const VMEXIT_SAVE_IA32_PAT: u64 = 1 << 18;
pub const VMEXIT_LOAD_IA32_PAT: u64 = 1 << 19;
pub const VMEXIT_SAVE_EFER: u64 = 1 << 20;
pub const VMEXIT_LOAD_EFER: u64 = 1 << 21;
pub const VMEXIT_SAVE_VMX_TIMER: u64 = 1 << 22;

pub const VMENTRY_LOAD_DBG_CONTROLS: u64 = 1 << 2;
pub const VMENTRY_GUEST_IA32E: u64 = 1 << 9;
pub const VMENTRY_SMM: u64 = 1 << 10;
pub const VMENTRY_DEACTIVATE_DUAL_MONITOR: u64 = 1 << 11;
pub const VMENTRY_LOAD_IA32_PERF_GLOBAL_CTRL: u64 = 1 << 13;
pub const VMENTRY_LOAD_IA32_PAT: u64 = 1 << 14;
pub const VMENTRY_LOAD_EFER: u64 = 1 << 15;

#[inline]
pub fn get_guest_reg(num: u64) -> X86Reg {
    [
        X86Reg::RAX,
        X86Reg::RCX,
        X86Reg::RDX,
        X86Reg::RBX,
        X86Reg::RSP,
        X86Reg::RBP,
        X86Reg::RSI,
        X86Reg::RDI,
        X86Reg::R8,
        X86Reg::R9,
        X86Reg::R10,
        X86Reg::R11,
        X86Reg::R12,
        X86Reg::R13,
        X86Reg::R14,
        X86Reg::R15,
    ][num as usize]
}
