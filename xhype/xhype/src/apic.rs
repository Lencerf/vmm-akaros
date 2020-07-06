use crate::err::Error;
use crate::hv::vmx::*;
use crate::mach::MachVMBlock;

const OFFSET_ICR: usize = 0x31;

pub struct Apic {
    x2mode: bool,
    apic_page: MachVMBlock,
}

impl Apic {
    pub fn new(x2mode: bool) -> Self {
        assert_eq!(x2mode, true); // support x2mode only for noe
        let apic_page = MachVMBlock::new(4096).unwrap();
        Apic { x2mode, apic_page }
    }

    pub fn read(&self, register: usize) -> Result<u64, Error> {
        if register < 0x40 {
            if register != OFFSET_ICR {
                Ok(self.apic_page.as_slice::<u32>()[register] as u64)
            } else {
                let low = self.apic_page.as_slice::<u32>()[register] as u64;
                let high = self.apic_page.as_slice::<u32>()[register + 1] as u64;
                Ok(low | (high << 32))
            }
        } else {
            Err(Error::Unhandled(
                VMX_REASON_APIC_ACCESS,
                "access a register larger than 0x40",
            ))
        }
    }
}
