use chrono::{Datelike, Timelike, Utc};
use log::*;

pub struct Rtc {
    pub reg: u8,
}

impl Rtc {
    pub fn read(&self, port: u16) -> u32 {
        match port {
            0x70 => self.reg as u32,
            0x71 => match self.reg {
                0x00 => Utc::now().naive_local().second(),
                0x02 => Utc::now().naive_local().minute(),
                0x04 => Utc::now().naive_local().hour(),
                0x06 => Utc::now().naive_local().weekday().number_from_sunday(),
                0x07 => Utc::now().naive_local().day(),
                0x08 => Utc::now().naive_local().month(),
                0x09 => Utc::now().naive_local().year() as u32 - 2000,
                0x0a => 0x20, //http://faydoc.tripod.com/structures/04/0406.htm
                0x0b => 0b10, // 24hour, http://faydoc.tripod.com/structures/04/0407.htm
                _ => {
                    warn!("return 0xff for unknown rtc register 0x{:x}", self.reg);
                    0xff
                }
            },
            _ => unreachable!(),
        }
    }
}
