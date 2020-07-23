//https://www.freebsd.org/doc/en_US.ISO8859-1/articles/serial-uart/index.html

use crate::print_stack;
use crate::utils::{cpu_memory_barrier, make_stdin_raw, read_stdin};
use crate::{print_cstr, print_cstr_file, print_file};
use bitfield::bitfield;
use log::*;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};

// offset 0x1, Interrupt Enable Register (IER)
bitfield! {
    #[derive(Copy, Clone, Debug)]
    struct Ier(u8);
    u8;
    edssi, _: 3,3; // Enable Modem Status Interrupt
    elsi, _: 2,2;  // Enable Receiver Line Status Interrupt
    etbei, _: 1,1; // Enable Transmitter Holding Register Empty Interrupt
    erbfi, _: 0,0; // Enable Received Data Available Interrupt
}

impl Default for Ier {
    fn default() -> Self {
        Ier(0) // disable all interrupts as default
    }
}

// offset 0x2, write, FIFO Control Register (FCR)
bitfield! {
    #[derive(Copy, Clone, Debug, Default)]
    struct Fcr(u8);
    u8;
    rtb, set_rtb: 7,6;    // receiver trigger bit
    dms, set_dms: 3,3;    // DMA Mode Select
    tfr, set_tfr: 2,2;    // Transmit FIFO Reset
    rfr, set_rfr: 1,1;    // Receiver FIFO Reset
    fifo, set_fifi: 0,0;  // 16550 FIFO Enable
}

// offset 0x2, read, Interrupt Identification Register
bitfield! {
    #[derive(Copy, Clone, Debug, Default)]
    struct Iir(u8);
    u8;
    intr_id, _: 3,1; // Interrupt ID
    pending, _: 0,0; // Interrupt Pending Bit
}

const DATA_AVAILABLE: u8 = 0b010;
const ROOM_AVAILABLE: u8 = 0b001;

// offset 0x3, Line Control Register (LCR)
bitfield! {
    #[derive(Copy, Clone, Debug)]
    struct Lcr(u8);
    u8;
    dlab, _: 7, 7;
    set_break, _: 6,6;
    stick_parity, _: 5,5;
    eps, _: 4,4;
    pen, _: 3,3;
    stb, _: 2,2;
    word_length, _: 1,0;
}

impl Default for Lcr {
    fn default() -> Self {
        Lcr(0b00000011) // 8 data bits as default
    }
}

// offset 0x4, Modem Control Register
bitfield! {
    #[derive(Copy, Clone, Debug)]
    struct Mcr(u8);
    u8;
    rts, _: 1,1;
    dtr, _: 0,0; // Data Terminal Ready
}

impl Default for Mcr {
    fn default() -> Self {
        Mcr(0) // Data Terminal Ready
    }
}

// offset 0x5, Line Status Register (LSR)
bitfield! {
    #[derive(Copy, Clone, Debug)]
    struct Lsr(u8);
    u8;
    err_fifo, _: 7,7;
    temt, _: 6,6; // transmitter empty
    thre, set_thre: 5,5; // transmitter holding register empty
    bi, _: 4,4; // break interrupt
    fe, _: 3,3; // framing error
    pe, _: 2,2; // parity error
    oe, _: 1,1; // overrun error
    ready, set_ready: 0,0; // data ready
}

impl Default for Lsr {
    fn default() -> Self {
        Lsr(0b01100000) // Transmitter Holding Register Empty (THRE)
    }
}

// TO-DO: send interrupts

#[derive(Debug)]
pub struct Serial {
    ier: Ier, // 0x1, Interrupt Enable Register (IER)
    fcr: Fcr, // 0x2, write, FIFO Control Register (FCR)
    iir: Iir, // 0x2, read, Interrupt Identification Register
    lcr: Lcr, // 0x3, Line Control Register (LCR)
    mcr: Mcr, // 0x4, Modem Control Register (MCR)
    lsr: Lsr, // 0x5, Line Status Register (LSR)
    msr: u8,  // 0x6, Modem Status Register (MSR)
    scr: u8,  // 0x7, Scratch Register (SCR)
    divisor: u16,
    in_data: Arc<RwLock<VecDeque<u8>>>,
    output_data: Vec<u8>,
    irq: u32,
    irq_sender: Sender<u32>,
}

impl Serial {
    pub fn new(irq: u32, irq_sender: Sender<u32>) -> Self {
        let in_data = Arc::new(RwLock::new(VecDeque::new()));
        let r = Serial {
            ier: Ier::default(),
            fcr: Fcr::default(),
            iir: Iir::default(),
            lcr: Lcr::default(),
            mcr: Mcr::default(),
            lsr: Lsr::default(),
            msr: 0,
            scr: 0,
            divisor: 0,
            in_data: in_data.clone(),
            output_data: Vec::new(),
            irq,
            irq_sender: irq_sender.clone(),
        };
        std::thread::Builder::new()
            .name(format!("serial thread irq {}", irq))
            .spawn(move || Self::input_loop(irq, irq_sender, in_data))
            .unwrap();
        r
    }

    fn input_loop(irq: u32, irq_sender: Sender<u32>, in_data: Arc<RwLock<VecDeque<u8>>>) {
        make_stdin_raw();
        loop {
            // std::thread::sleep(std::time::Duration::from_secs(10));
            // continue;
            let c = read_stdin();
            // std::io::stdin().read_line(&mut buf).unwrap();
            // debug_assert_eq!(buf.len(), 1);
            {
                let mut in_data = in_data.write().unwrap();
                let len = in_data.len();
                in_data.push_back(c);
                if in_data.len() > len {
                    drop(in_data);
                } else {
                    panic!();
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
            irq_sender.send(irq).unwrap();

            // std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
            // let output = format!("get char = {:x} {}\n", c, c as char);
            // unsafe {
            //     print_file(
            //         output.as_ptr(),
            //         output.len() as u64,
            //         "/Users/changyuanl/test/printc_output/com1read.txt\0".as_ptr(),
            //     )
            // }
        }
    }

    pub fn read(&mut self, offset: u16) -> u8 {
        let result = match offset {
            0 => {
                if self.lcr.dlab() == 0 {
                    let ret = {
                        let mut in_data = self.in_data.write().unwrap();
                        in_data.pop_front().unwrap_or(b'a')
                    };
                    // let output = if ret != 0xff {
                    //     format!("host read 0x{:x} {} from queue\n", ret, ret as char)
                    // } else {
                    //     "no data in queue\n".to_string()
                    // };
                    // unsafe {
                    //     print_file(
                    //         output.as_ptr(),
                    //         output.len() as u64,
                    //         "/Users/changyuanl/test/printc_output/com1read.txt\0".as_ptr(),
                    //     )
                    // }

                    // let ret = if in_data.len() > 0 {
                    //     let c = in_data[0].pop_front().unwrap();
                    //     if in_data[0].len() == 0 {
                    //         in_data.pop_front();
                    //     }
                    //     unsafe {
                    //         print_file(
                    //             &c,
                    //             1,
                    //             "/Users/changyuanl/test/printc_output/com1read.txt\0".as_ptr(),
                    //         )
                    //     }
                    //     c
                    // } else {
                    //     warn!("OS read from serial port, no data, return 0xff");
                    //     0xff
                    // };
                    // if in_data.len() > 0 {
                    //     self.irq_sender.send(self.irq).unwrap();
                    // }
                    ret
                } else {
                    (self.divisor & 0xff) as u8
                }
            }
            1 => {
                if self.lcr.dlab() == 0 {
                    self.ier.0
                } else {
                    (self.divisor >> 8) as u8
                }
            }
            2 => {
                let r = if self.in_data.read().unwrap().len() > 0 {
                    DATA_AVAILABLE << 1
                } else {
                    ROOM_AVAILABLE << 1
                };
                // unsafe {
                //     print_cstr_file(&r, )
                // }
                r
            }
            3 => self.lcr.0,
            4 => self.mcr.0,
            5 => {
                let in_data_len = { self.in_data.read().unwrap().len() };
                if in_data_len == 0 {
                    self.lsr.set_ready(0);
                } else {
                    self.lsr.set_ready(1);
                }
                self.lsr.set_thre(1);
                self.lsr.0
            }
            6 => self.msr,
            7 => self.scr,
            _ => unreachable!("offset {}", offset),
        };
        // if offset != 0 && offset != 5 {
        //     println!("read {:08b} from offset {}", result, offset);
        // }
        result
    }

    pub fn write(&mut self, offset: u16, value: u8) {
        info!("write {:08b} to offset {}", value, offset);
        match offset {
            0 => {
                if self.lcr.dlab() == 0 {
                    unsafe {
                        print_cstr_file(
                            &value,
                            1,
                            "/Users/changyuanl/test/printc_output/com1write.txt\0".as_ptr(),
                        )
                    }
                // self.output_data.push(value);
                // if value == b'\n' || value == b'\r' {
                //     let data = std::mem::replace(&mut self.output_data, Vec::new());
                //     let line = String::from_utf8(data).unwrap();
                //     print!("{}", line);
                //     std::io::stdout().flush().unwrap();
                // }
                // self.irq_sender.send(self.irq).unwrap();
                } else {
                    self.divisor &= !0xff;
                    self.divisor |= value as u16;
                }
            }
            1 => {
                if self.lcr.dlab() == 0 {
                    self.ier.0 = value
                } else {
                    self.divisor &= 0xff;
                    self.divisor |= (value as u16) << 8;
                }
            }
            2 => self.fcr.0 = value,
            3 => self.lcr.0 = value,
            4 => {
                self.mcr.0 = value;
            }
            5 => self.lsr.0 = value,
            6 => {
                self.msr = value;
                panic!("msr write");
            }
            7 => self.scr = value,
            _ => unreachable!("offset {}, value = {:b}", offset, value),
        }
    }
}
