/* SPDX-License-Identifier: GPL-2.0-only */
use crate::hv::interrupt_vcpu;
use crate::{Error, GuestThread, VCPU};
use bitfield::bitfield;
#[allow(unused_imports)]
use log::*;

use std::sync::{
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex, RwLock,
};
// bitfield! {
//     struct IoApicEntry(u64);
//     u64;
//     vector, _: 0,7;
//     delivery_mode, _: 8,10;
//     destination_mode, _: 11, 11;
//     delivery_status, _: 12, 12;
//     pin_priority, _: 13, 13;
//     remote_irr, _: 14, 14;
//     trigger_mode, _: 15,15;
//     mask,_:16,16;
//     destination, _: 56,63;
// }

// fn tb_vector(reg: u64) -> u8 {
//     (reg & 0xff) as u8
// }

// fn delivery_mode(reg: u64) -> u8 {
//     ((reg >> 8) & 0b111) as u8
// }

// fn destination_mode(reg: u64) -> &'static str {
//     if (reg >> 11) & 1 == 1 {
//         "logical"
//     } else {
//         "physical"
//     }
// }

// fn delivery_status(reg: u64) -> &'static str {
//     if (reg >> 12) & 1 == 1 {
//         "sent"
//     } else {
//         "pending"
//     }
// }

// fn pin_priority(reg: u64) -> &'static str {
//     if (reg >> 13) & 1 == 1 {
//         "low"
//     } else {
//         "high"
//     }
// }

// fn irr(reg: u64) -> u8 {
//     ((reg >> 14) & 1) as u8
// }

// fn trigger_mode(reg: u64) -> &'static str {
//     if (reg >> 15) & 1 == 1 {
//         "level"
//     } else {
//         "edge"
//     }
// }

// fn mask(reg: u64) -> bool {
//     (reg >> 16) & 1 == 1
// }

// fn destination(reg: u64) -> u8 {
//     (reg >> 56 & 0xf) as u8
// }

const IOAPIC_NUM_PINS: u32 = 24;

pub struct IoApic {
    id: u32,
    reg: u32,
    arbid: u32,
    pub value: [u32; 256],
}

impl IoApic {
    pub fn new() -> Self {
        IoApic {
            id: 0,
            reg: 0,
            arbid: 0,
            value: [0; 256],
        }
    }

    pub fn dispatch(
        intr_senders: Arc<Mutex<Option<Vec<Sender<u8>>>>>,
        irq_receiver: Receiver<u32>,
        ioapic: Arc<RwLock<IoApic>>,
        vcpu_ids: Arc<RwLock<Vec<u32>>>,
    ) {
        loop {
            let irq = irq_receiver.recv().unwrap();
            let ioapic = ioapic.read().unwrap();
            let vcpu_ids = vcpu_ids.read().unwrap();
            let entry = ioapic.value[2 * irq as usize] as u64
                | ((ioapic.value[2 * irq as usize + 1] as u64) << 32);
            let vector = (entry & 0xff) as u8;
            let dest = entry >> 56;
            let senders = intr_senders.lock().unwrap();
            if let Some(ref some_senders) = *senders {
                // println!(
                //     "get irq = {}, entry = {:x} vector = {:x}",
                //     irq, entry, vector
                // );
                if entry & (1 << 11) == 0 {
                    // physical mode
                    let dest = (dest & 0b1111) as usize;
                    some_senders[dest].send(vector).unwrap();
                    interrupt_vcpu(&vcpu_ids[dest..(dest + 1)]).unwrap();
                } else {
                    // logical destination mode
                    for i in 0..8 {
                        if dest & (1 << i) != 0 {
                            some_senders[i].send(vector).unwrap();
                            interrupt_vcpu(&vcpu_ids[i..(i + 1)]).unwrap();
                        }
                    }
                }
            } else {
                println!("sender is none");
            }
            // println!("data in io apic = {:x}", entry);
            // println!("ioapic data = {:?}", &ioapic.value[0..32]);
        }
    }
}

fn ioapic_write(gth: &GuestThread, offset: usize, value: u32) {
    let mut ioapic = gth.vm.ioapic.write().unwrap();
    if offset == 0 {
        warn!("ioapic_write set reg {:x}", value);
        ioapic.reg = value;
    } else {
        match ioapic.reg {
            0 => ioapic.id = value,
            1 | 2 => unimplemented!(),
            reg => {
                ioapic.value[reg as usize - 0x10] = value;
                println!(
                    "OS write {:x} to {:x}, need to change virtio device irqs",
                    ioapic.value[reg as usize - 0x10],
                    reg
                );
                // println!("{:?}", &ioapic.value[0..32])
                // let full = if reg % 2 == 0 {
                //     ioapic.value[reg as usize - 0x10] as u64
                //         | ((ioapic.value[reg as usize + 1 - 0x10] as u64) << 32)
                // } else {
                //     ioapic.value[reg as usize - 0x10 - 1] as u64
                //         | ((ioapic.value[reg as usize - 0x10] as u64) << 32)
                // };
                // if reg % 2 == 0 {
                //     let irq = reg - 0x10;
                //     let vm = gth.vm.write().unwrap();
                //     vm.virtio_mmio_dev[irq as usize].vec
                // }
                // println!("vec = {:x}, delivery_mode={}, dest_mode = {}, dev_status = {}, priority = {}, irr = {}, mode = {}, maks = {}, dest = {}", tb_vector(full), delivery_mode(full), destination_mode(full), delivery_status(full), pin_priority(full), irr(full), trigger_mode(full), mask(full), destination(full));
            }
        }
    }
}

fn ioapic_read(gth: &GuestThread, offset: usize) -> u32 {
    let ioapic = gth.vm.ioapic.read().unwrap();
    let reg = ioapic.reg;
    if offset == 0 {
        reg
    } else {
        let ret = match reg {
            0 => ioapic.id,
            1 => 0x170011,
            2 => ioapic.arbid,
            _ => {
                if reg < (IOAPIC_NUM_PINS * 2 + 0x10) {
                    ioapic.value[reg as usize - 0x10]
                } else {
                    warn!("IO APIC read bad reg {:x}", reg);
                    0xffffffff
                }
            }
        };
        warn!("IO APIC read reg {:x} return {:x}", reg, ret);
        ret
    }
}

pub fn ioapic_access(
    _vcpu: &VCPU,
    gth: &mut GuestThread,
    gpa: usize,
    reg_val: &mut u64,
    _size: u8,
    store: bool,
) -> Result<(), Error> {
    let offset = gpa & 0xfffff;
    if offset != 0 && offset != 0x10 {
        warn!(
            "Bad register offset: {:x} and has to be 0x0 or 0x10",
            offset
        );
        return Ok(());
    }
    if store {
        ioapic_write(gth, offset, *reg_val as u32);
    } else {
        *reg_val = ioapic_read(gth, offset) as u64;
    }
    Ok(())
}
