use crate::err::Error;
use crate::hv::vmx::*;
use crate::mach::MachVMBlock;
use crate::GuestThread;
#[allow(unused_imports)]
use log::*;

const OFFSET_ID: usize = 0x20;
const OFFSET_VER: usize = 0x30;
const OFFSET_TPR: usize = 0x80;
const OFFSET_APR: usize = 0x90;
const OFFSET_PPR: usize = 0xa0;
const OFFSET_EOI: usize = 0xb0;
const OFFSET_RRD: usize = 0xc0;
const OFFSET_LOGICAL_DEST: usize = 0xd0;
const OFFSET_DEST_FORMAT: usize = 0xe0;
const OFFSET_SIV: usize = 0xf0;
const OFFSET_ISR0: usize = 0x100;
const OFFSET_ISR32: usize = 0x110;
const OFFSET_ISR64: usize = 0x120;
const OFFSET_ISR96: usize = 0x130;
const OFFSET_ISR128: usize = 0x140;
const OFFSET_ISR160: usize = 0x150;
const OFFSET_ISR192: usize = 0x160;
const OFFSET_ISR224: usize = 0x170;
const OFFSET_TMR0: usize = 0x180;
const OFFSET_TMR32: usize = 0x190;
const OFFSET_TMR64: usize = 0x1a0;
const OFFSET_TMR96: usize = 0x1b0;
const OFFSET_TMR128: usize = 0x1c0;
const OFFSET_TMR160: usize = 0x1d0;
const OFFSET_TMR192: usize = 0x1e0;
const OFFSET_TMR224: usize = 0x1f0;
const OFFSET_IRR0: usize = 0x200;
const OFFSET_IRR32: usize = 0x210;
const OFFSET_IRR64: usize = 0x220;
const OFFSET_IRR96: usize = 0x230;
const OFFSET_IRR128: usize = 0x240;
const OFFSET_IRR160: usize = 0x250;
const OFFSET_IRR192: usize = 0x260;
const OFFSET_IRR224: usize = 0x270;
const OFFSET_ERROR_STATUS: usize = 0x280;
const OFFSET_LVT_CMCI: usize = 0x2f0;
const OFFSET_ICR0: usize = 0x300; // inter-processor interrupt
const OFFSET_ICR32: usize = 0x310;
const OFFSET_LVT_TIMER: usize = 0x320;
const OFFSET_LVT_THERMAL: usize = 0x330;
const OFFSET_LVT_PERF: usize = 0x340;
const OFFSET_LVT_LINT0: usize = 0x350;
const OFFSET_LVT_LINT1: usize = 0x360;
const OFFSET_LVT_ERROR: usize = 0x370;
const OFFSET_INIT_COUNT: usize = 0x380;
const OFFSET_CURR_COUNT: usize = 0x390;
const OFFSET_DIV_CONF: usize = 0x3e0;

const APIC_VER: u32 = 0x10;

pub struct Apic {
    pub id: u32,
    pub msr_apic_base: u64,
    pub apic_page: MachVMBlock,
}

impl Apic {
    pub fn new(base: u64, enabled: bool, x2mode: bool, id: u32, bsp: bool) -> Self {
        debug_assert_eq!(x2mode, false);
        let apic_page = MachVMBlock::new(4096).unwrap();
        let msr_apic_base = base
            | if enabled { 1 << 11 } else { 0 }
            | if x2mode { 1 << 10 } else { 0 }
            | if bsp { 1 << 8 } else { 0 };
        let mut apic = Apic {
            msr_apic_base,
            apic_page,
            id,
        };
        apic.reset();
        apic
    }

    pub fn read(&self, offset: usize) -> Result<u64, Error> {
        if offset < 0x400 {
            Ok(self.apic_page.read::<u32>(offset, 0) as u64)
        } else {
            Err(Error::Program("access a register larger than 0x40"))
        }
    }

    pub fn write(&mut self, offset: usize, value: u64) -> Result<(), Error> {
        if offset < 0x400 {
            self.apic_page.write(value as u32, offset, 0);
            Ok(())
        } else {
            Err(Error::Program("write a register larger than 0x40"))
        }
    }

    //10.4.7.1 Local APIC State After Power-Up or Reset
    pub fn reset(&mut self) {
        self.apic_page.write(self.id as u32, OFFSET_ID, 0);
        self.apic_page
            .write(APIC_VER | (6 << 16) as u32, OFFSET_VER, 0);
        // Figure 10-18. Task-Priority Register (TPR)
        self.apic_page.write(0u32, OFFSET_TPR, 0);
        // Figure 10-15. Arbitration Priority Register (APR)
        self.apic_page.write(0u32, OFFSET_APR, 0);
        // Figure 10-19. Processor-Priority Register (PPR)
        self.apic_page.write(0u32, OFFSET_PPR, 0);
        // Figure 10-13. Logical Destination Register (LDR)
        self.apic_page.write(0u32, OFFSET_LOGICAL_DEST, 0);
        // Figure 10-14. Destination Format Register (DFR)
        self.apic_page.write(0xffffffffu32, OFFSET_DEST_FORMAT, 0);
        self.apic_page.write(0xffu32, OFFSET_SIV, 0);

        // reset IRR, ISR, TMR, Figure 10-20. IRR, ISR and TMR Registers
        for i in 0..(256 / 32) {
            self.apic_page.write(0u32, OFFSET_TMR0 + i * 0x10, 0);
            self.apic_page.write(0u32, OFFSET_ISR0 + i * 0x10, 0);
            self.apic_page.write(0u32, OFFSET_ISR0 + i * 0x10, 0);
        }

        // Figure 10-9. Error Status Register (ESR)
        self.apic_page.write(0u32, OFFSET_ERROR_STATUS, 0);

        // reset LVT, Figure 10-8. Local Vector Table (LVT)
        let lvt_init: u32 = 0x10000;
        self.apic_page.write(lvt_init, OFFSET_LVT_CMCI, 0);
        self.apic_page.write(lvt_init, OFFSET_LVT_TIMER, 0);
        self.apic_page.write(lvt_init, OFFSET_LVT_THERMAL, 0);
        self.apic_page.write(lvt_init, OFFSET_LVT_PERF, 0);
        self.apic_page.write(lvt_init, OFFSET_LVT_LINT0, 0);
        self.apic_page.write(lvt_init, OFFSET_LVT_LINT1, 0);
        self.apic_page.write(lvt_init, OFFSET_LVT_ERROR, 0);

        // Figure 10-12. Interrupt Command Register (ICR)
        self.apic_page.write(0u32, OFFSET_ICR0, 0);
        self.apic_page.write(0u32, OFFSET_ICR32, 0);

        // Figure 10-10. Divide Configuration Register
        self.apic_page.write(0u32, OFFSET_DIV_CONF, 0);
        self.apic_page.write(0u32, OFFSET_CURR_COUNT, 0);
        self.apic_page.write(0u32, OFFSET_INIT_COUNT, 0);
    }
}

pub fn apic_access(
    gth: &mut GuestThread,
    gpa: usize,
    reg_val: &mut u64,
    _size: u8,
    store: bool,
) -> Result<(), Error> {
    let offset = gpa & 0xfffff;
    if store {
        warn!(
            "store 0x{:x} to gpa = 0x{:x} offset = 0x{:x}",
            *reg_val, gpa, offset
        );
        gth.apic.write(offset, *reg_val)?;
        Ok(())
    // Err(Error::Program("apic write unimplemented"))
    } else {
        *reg_val = gth.apic.read(offset)?;
        warn!(
            "read {:x} from gap = {:x}, offset = {:x}",
            *reg_val, gpa, offset
        );
        Ok(())
    }
}
