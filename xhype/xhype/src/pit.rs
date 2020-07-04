use crate::hv::vmx::*;
use crate::{Error, GuestThread, HandleResult, X86Reg, VCPU};
#[allow(unused_imports)]
use log::*;
#[allow(unused_imports)]
use std::time::SystemTime;

pub struct PitChannel {
    pub access_mode: u8,
    pub op_mode: u8,
    pub reload: u16,
    pub counter: u16,
    pub latch_value: Option<u16>,
    pub reload_index: usize,
    pub last_time: SystemTime,
    pub read_index: usize,
}

impl Default for PitChannel {
    fn default() -> Self {
        PitChannel {
            access_mode: 0,
            op_mode: 0,
            reload: 0,
            counter: 0,
            latch_value: None,
            reload_index: 0,
            last_time: SystemTime::now(),
            read_index: 0,
        }
    }
}

pub const PIT_FREQ_HZ: u128 = 1193182;

impl PitChannel {
    pub fn update_counter(&mut self) -> u16 {
        let now = SystemTime::now();
        let time_elapsed = now.duration_since(self.last_time).unwrap().as_micros();
        let num_pulse = PIT_FREQ_HZ * time_elapsed / 1000000;
        self.last_time = now;
        let delta = (num_pulse % self.reload as u128) as u16;
        // fix me, can be optimized
        if delta <= self.counter {
            self.counter -= delta;
        } else {
            self.counter = 65535 - (delta - self.counter);
        }
        // info!("update counter to {:x}", self.counter);
        self.counter
    }
}

#[derive(Default)]
pub struct Pit {
    channels: [PitChannel; 3],
}

const PIT_READ_BACK: u8 = 0b11;
const PIT_LATCH: u8 = 0b00;
const PIT_LO: u8 = 0b01;
const PIT_HI: u8 = 0b10;
const PIT_LO_HI: u8 = 0b11;

pub fn pit_data_handle(
    vcpu: &VCPU,
    gth: &GuestThread,
    port: u16,
    r#in: bool,
) -> Result<HandleResult, Error> {
    let channel_num = port - 0x40;
    let mut vm_ = gth.vm.write().unwrap();
    let mut channel = &mut vm_.pit.channels[channel_num as usize];
    if r#in {
        // read counter value
        let value = if let Some(latched_value) = channel.latch_value {
            latched_value
        } else {
            channel.update_counter()
        };
        let result = if channel.read_index == 0 {
            value & 0xff
        } else {
            (value >> 8) & 0xff
        } as u64;
        // info!("result = {:x}", result);
        channel.read_index = 1 - channel.read_index;
        if channel.read_index == 0 && channel.latch_value.is_some() {
            channel.latch_value = None;
        }
        let rax = vcpu.read_reg(X86Reg::RAX)?;
        let rax_new = (rax & !0xff) | result;
        // info!("{:x}, {:x}", (rax & !0xff), rax_new);
        vcpu.write_reg(X86Reg::RAX, rax_new)?;
        warn!("request from port {:x}, return {:x}", port, result);
        Ok(HandleResult::Next)
    } else {
        let data = (vcpu.read_reg(X86Reg::RAX)? & 0xff) as u8;
        // set reload value
        info!("accept data {:x} from port {:x}", data, port);
        if channel.reload_index == 1 {
            channel.last_time = SystemTime::now();
            channel.reload |= (data as u16) << 8;
            channel.counter = channel.reload;
            info!(
                "set channel {} reload value to {:02x?}",
                channel_num, channel.reload
            );
            if channel_num == 0 {
                warn!("should start a thread to send interrupt");
            }
        } else {
            channel.reload = data as u16;
        }
        channel.reload_index = 1 - channel.reload_index;
        Ok(HandleResult::Next)
    }
}

pub fn pit_cmd_handler(vcpu: &VCPU, gth: &GuestThread) -> Result<HandleResult, Error> {
    let cmd = (vcpu.read_reg(X86Reg::RAX)? & 0xff) as u8;
    let channel_num = cmd >> 6;
    let access_mode = (cmd >> 4) & 0b11;
    let op_mode = (cmd >> 1) & 0b111;
    let binary_mode = cmd & 0b1 == 0;
    if !binary_mode {
        return Err((VMX_REASON_IO, "only binary mode of PIT is allowed"))?;
    }
    if channel_num == PIT_READ_BACK {
        return Err((VMX_REASON_IO, "read back mode not supported"))?;
    }
    let mut vm_ = gth.vm.write().unwrap();
    let mut channel = &mut vm_.pit.channels[channel_num as usize];
    channel.access_mode = access_mode;
    channel.op_mode = op_mode;
    if op_mode != 0 && op_mode != 2 {
        return Err((VMX_REASON_IO, "only opmode 0 and 2 are supported"))?;
    }
    info!(
        "write {:x} to PIC cmd port, channel = {}, access_mode = {}, op_mode = {}",
        cmd, channel_num, access_mode, op_mode
    );
    match access_mode {
        PIT_LO_HI => Ok(HandleResult::Next),
        _ => Err((VMX_REASON_IO, "only lobyte/hibyte is supported"))?,
    }
}
