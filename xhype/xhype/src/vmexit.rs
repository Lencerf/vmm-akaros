/* SPDX-License-Identifier: GPL-2.0-only */

#[allow(unused_imports)]
use super::consts::msr::*;
#[allow(unused_imports)]
use super::hv::vmx::*;
#[allow(unused_imports)]
use super::x86::*;
use super::{Error, GuestThread, X86Reg, VCPU};
use crate::apic::apic_access;
use crate::cpuid::do_cpuid;
use crate::decode::emulate_mem_insn;
#[allow(unused_imports)]
use crate::hv::{vmx_read_capability, VMXCap};
use crate::ioapic::ioapic_access;
use crate::pit::{pit_cmd_handler, pit_data_handle};
use crate::utils::{get_bus_frequency, get_tsc_frequency};
use log::{error, info, trace, warn};
use std::mem::size_of;

#[derive(Debug, Eq, PartialEq)]
pub enum HandleResult {
    Exit,
    Resume,
    Next,
}

pub fn make_vm_entry_intr_info(
    vcpu: &VCPU,
    vector: u8,
    r#type: u8,
    code: Option<u32>,
) -> Result<(), Error> {
    // fix me: need to check Interruptibility
    if let Some(code) = code {
        vcpu.write_vmcs(VMCS_CTRL_VMENTRY_EXC_ERROR, code as u64)?;
        let info = 1 << 31 | vector as u64 | (r#type as u64) << 8 | 1 << 11;
        vcpu.write_vmcs(VMCS_CTRL_VMENTRY_IRQ_INFO, info)?;
    } else {
        let info = 1 << 31 | vector as u64 | (r#type as u64) << 8;
        vcpu.write_vmcs(VMCS_CTRL_VMENTRY_IRQ_INFO, info)?;
    }
    Ok(())
}

// Fix me!
// this function is extremely unsafe. The purpose is to read from guest's memory,
// since the high memory address are the same as the host, we just directly read
// the host's memory. There should be better ways to implement this.
pub fn read_host_mem<T>(base: u64, index: u64) -> T {
    // println!("read from base = {:x}, index = {}", base, index);
    let ptr = (base + index * size_of::<T>() as u64) as *const T;
    unsafe { ptr.read() }
}

fn pt_index(addr: u64) -> u64 {
    (addr >> 12) & 0x1ff
}

fn pd_index(addr: u64) -> u64 {
    (addr >> 21) & 0x1ff
}

fn pdpt_index(addr: u64) -> u64 {
    (addr >> 30) & 0x1ff
}

fn pml4_index(addr: u64) -> u64 {
    (addr >> 39) & 0x1ff
}

const ADDR_MASK: u64 = 0xffffffffffff;
pub fn simulate_paging(vcpu: &VCPU, addr_v: u64) -> Result<u64, Error> {
    let addr_v = ADDR_MASK & addr_v;
    // println!("addr_v = {:x}", addr_v);
    let cr0 = vcpu.read_reg(X86Reg::CR0)?;
    if cr0 & X86_CR0_PG == 0 {
        return Ok(addr_v);
    }
    let cr3 = vcpu.read_reg(X86Reg::CR3)?;
    // println!("cr3 = {:x}", cr3);
    let pml4e: u64 = read_host_mem((cr3 & !0xfff) & ADDR_MASK, pml4_index(addr_v));
    // println!("pml4e = {:x}", pml4e);
    if pml4e & PG_P == 0 {
        return Err("simulate_paging: page fault at pml4e")?;
    }
    let pdpte: u64 = read_host_mem((pml4e & !0xfff) & ADDR_MASK, pdpt_index(addr_v));
    // println!("pdpte = {:x}", pdpte);
    if pdpte & PG_P == 0 {
        return Err("simulate_paging: page fault at pdpte")?;
    } else if pdpte & PG_PS > 0 {
        return Ok((pdpte & !0x3fffffff) | (addr_v & 0x3fffffff));
    }
    let pde: u64 = read_host_mem((pdpte & !0xfff) & ADDR_MASK, pd_index(addr_v));
    // println!("pde = {:x}", pde);
    if pde & PG_P == 0 {
        return Err("simulate_paging: page fault at pde")?;
    } else if pde & PG_PS > 0 {
        return Ok((pde & !0x1fffff) | (addr_v & 0x1fffff));
    }
    let pte: u64 = read_host_mem((pde & !0xfff) & ADDR_MASK, pt_index(addr_v));
    // println!("pte = {:x}", pte);
    if pte & PG_P == 0 {
        return Err("simulate_paging: page fault at pte")?;
    } else {
        Ok(((pte & !0xfff) | (addr_v & 0xfff)) & ADDR_MASK)
    }
}

#[allow(dead_code)]
pub fn get_vmexit_instr(vcpu: &VCPU) -> Result<Vec<u8>, Error> {
    let len = vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
    let rip_v = vcpu.read_vmcs(VMCS_GUEST_RIP)?;
    let rip = simulate_paging(&vcpu, rip_v)?;
    Ok((0..len).map(|i| read_host_mem::<u8>(rip, i)).collect())
}

#[allow(dead_code)]
pub fn get_vmexit_instr_more(vcpu: &VCPU, before: u64, after: u64) -> Result<[Vec<u8>; 3], Error> {
    let len = vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
    let rip_v = vcpu.read_vmcs(VMCS_GUEST_RIP)?;
    let rip = simulate_paging(&vcpu, rip_v)?;
    Ok([
        (0..before)
            .map(|i| read_host_mem::<u8>(rip - before, i))
            .collect(),
        (0..len).map(|i| read_host_mem::<u8>(rip, i)).collect(),
        (0..after)
            .map(|i| read_host_mem::<u8>(rip + len, i))
            .collect(),
    ])
}

////////////////////////////////////////////////////////////////////////////////
// VMX_REASON_MOV_CR
////////////////////////////////////////////////////////////////////////////////

fn get_creg(num: u64) -> X86Reg {
    match num {
        0 => X86Reg::CR0,
        4 => X86Reg::CR4,
        _ => unreachable!(),
    }
}

pub fn handle_cr(vcpu: &VCPU, _gth: &GuestThread) -> Result<HandleResult, Error> {
    let qual = vcpu.read_vmcs(VMCS_RO_EXIT_QUALIFIC)?;
    let creg = get_creg(qual & 0xf);
    let access_type = (qual << 4) & 0b11;
    let lmsw_type = (qual << 6) & 0b1;
    let reg = get_guest_reg((qual << 8) & 0xf);
    let source_data = (qual << 16) & 0xffff;
    let old_value = vcpu.read_reg(creg)?;
    info!(
        "{:?}={:x}, access={:x}, lmsw_type={:x}, reg={:?}, source={:x}",
        creg, old_value, access_type, lmsw_type, reg, source_data
    );
    match access_type {
        0 => {
            // move to cr
            let mut new_value = vcpu.read_reg(reg)?;
            if creg == X86Reg::CR0 {
                new_value |= X86_CR0_NE;
                vcpu.write_vmcs(VMCS_CTRL_CR0_SHADOW, new_value)?;
                let mut efer = vcpu.read_vmcs(VMCS_GUEST_IA32_EFER)?;
                let cr4 = vcpu.read_reg(X86Reg::CR4)?;
                let long_mode = new_value & X86_CR0_PE > 0
                    && new_value & X86_CR0_PG > 0
                    && cr4 & X86_CR4_PAE > 0
                    && efer & X86_EFER_LME > 0;
                if long_mode && efer & X86_EFER_LMA == 0 {
                    efer |= X86_EFER_LMA;
                    vcpu.write_vmcs(VMCS_GUEST_IA32_EFER, efer)?;
                    let mut ctrl_entry = vcpu.read_vmcs(VMCS_CTRL_VMENTRY_CONTROLS)?;
                    ctrl_entry |= VMENTRY_GUEST_IA32E;
                    vcpu.write_vmcs(VMCS_CTRL_VMENTRY_CONTROLS, ctrl_entry)?;
                    info!("turn on LMA");
                }
                if !long_mode && efer & X86_EFER_LMA > 0 {
                    efer &= !X86_EFER_LMA;
                    vcpu.write_vmcs(VMCS_GUEST_IA32_EFER, efer)?;
                    let mut ctrl_entry = vcpu.read_vmcs(VMCS_CTRL_VMENTRY_CONTROLS)?;
                    ctrl_entry &= !VMENTRY_GUEST_IA32E;
                    vcpu.write_vmcs(VMCS_CTRL_VMENTRY_CONTROLS, ctrl_entry)?;
                    info!("turn off LMA");
                }
            } else {
                unimplemented!();
            }
            vcpu.write_reg(creg, new_value)?;
            info!("update {:?} to {:x}", creg, new_value);
        }
        _ => unimplemented!(),
    }

    Ok(HandleResult::Next)
}

////////////////////////////////////////////////////////////////////////////////
// VMX_REASON_RDMSR, VMX_REASON_WRMSR
////////////////////////////////////////////////////////////////////////////////

struct MSRHander(
    pub u32,
    pub fn(u32, bool, u64, &VCPU, &GuestThread) -> Result<HandleResult, Error>,
);

#[inline]
fn write_msr_to_reg(msr_value: u64, vcpu: &VCPU) -> Result<HandleResult, Error> {
    let new_eax = msr_value & 0xffffffff;
    let new_edx = msr_value >> 32;
    vcpu.write_reg(X86Reg::RAX, new_eax)?;
    vcpu.write_reg(X86Reg::RDX, new_edx)?;
    info!("return msr value = {:x}", msr_value);
    Ok(HandleResult::Next)
}

fn emsr_unimpl(
    msr: u32,
    read: bool,
    new_value: u64,
    _vcpu: &VCPU,
    _gth: &GuestThread,
) -> Result<HandleResult, Error> {
    if read {
        error!("read from unknown msr: {:08x}", msr);
        Err(Error::Unhandled(VMX_REASON_RDMSR, "unknown msr"))
    } else {
        error!("write {:x} to unknown msr: {:08x} ", new_value, msr);
        Err(Error::Unhandled(VMX_REASON_WRMSR, "unknown msr"))
    }
}

fn emsr_gp(
    msr: u32,
    read: bool,
    new_value: u64,
    vcpu: &VCPU,
    _gth: &GuestThread,
) -> Result<HandleResult, Error> {
    if read {
        error!("read from non-existing msr: {:08x}, generate GP", msr);
        make_vm_entry_intr_info(vcpu, 13, 3, Some(0))?;
        Ok(HandleResult::Resume)
    } else {
        error!("write {:x} to unknown msr: {:08x} ", new_value, msr);
        Err(Error::Unhandled(VMX_REASON_WRMSR, "unknown msr"))
    }
}

/*
 * Set mandatory bits
 *  11:   branch trace disabled
 *  12:   PEBS unavailable
 * Clear unsupported features
 *  16:   SpeedStep enable
 *  18:   enable MONITOR FSM
 */
// FIX ME!
fn emsr_miscenable(
    _msr: u32,
    read: bool,
    new_value: u64,
    vcpu: &VCPU,
    _gth: &GuestThread,
) -> Result<HandleResult, Error> {
    let misc_enable = 1 | ((1 << 12) | (1 << 11)) & !((1 << 18) | (1 << 16));
    if read {
        write_msr_to_reg(misc_enable, vcpu)
    } else {
        if new_value == misc_enable {
            Ok(HandleResult::Next)
        } else {
            error!("just accept misc_enable {:x}", new_value);

            Ok(HandleResult::Next)
            // Err(Error::Unhandled(
            //     VMX_REASON_WRMSR,
            //     "write a different value to misc_enable, 0x1a0",
            // ))
        }
    }
}

fn emsr_platform_info(
    _msr: u32,
    read: bool,
    _new_value: u64,
    vcpu: &VCPU,
    _gth: &GuestThread,
) -> Result<HandleResult, Error> {
    let ratio = (get_tsc_frequency() / get_bus_frequency()) & 0xff;
    let platform_info = (ratio << 8) | (ratio << 40);
    if read {
        write_msr_to_reg(platform_info, vcpu)
    } else {
        Err(Error::Unhandled(
            VMX_REASON_WRMSR,
            "platform info msr is read-only",
        ))
    }
}

fn emsr_efer(
    _msr: u32,
    read: bool,
    new_value: u64,
    vcpu: &VCPU,
    _gth: &GuestThread,
) -> Result<HandleResult, Error> {
    if read {
        let value = vcpu.read_vmcs(VMCS_GUEST_IA32_EFER)?;
        write_msr_to_reg(value, vcpu)
    } else {
        vcpu.write_vmcs(VMCS_GUEST_IA32_EFER, new_value)?;
        Ok(HandleResult::Next)
    }
}

fn emsr_rdonly(
    msr: u32,
    read: bool,
    new_value: u64,
    vcpu: &VCPU,
    _gth: &GuestThread,
) -> Result<HandleResult, Error> {
    if read {
        let r = match msr {
            MSR_MTRRCAP
            | MSR_MTRRDEF_TYPE
            | MSR_IA32_BIOS_SIGN_ID
            | MSR_IA32_MCG_CAP
            | MISC_FEATURE_ENABLES
            | MSR_IA32_MCG_STATUS => 0,
            _ => unreachable!(),
        };
        write_msr_to_reg(r, vcpu)
    } else {
        warn!("write {:x} to read-only msr {:x}", new_value, msr);
        Ok(HandleResult::Next)
    }
}

fn emsr_pat(
    _msr: u32,
    read: bool,
    new_value: u64,
    vcpu: &VCPU,
    gth: &GuestThread,
) -> Result<HandleResult, Error> {
    // unimplemented!();
    if read {
        write_msr_to_reg(gth.msr_pat.get(), vcpu)
    } else {
        gth.msr_pat.set(new_value);
        Ok(HandleResult::Next)
    }
}

static mut apic_count: i32 = 1;

fn emsr_apicbase(
    _msr: u32,
    read: bool,
    new_value: u64,
    vcpu: &VCPU,
    gth: &GuestThread,
) -> Result<HandleResult, Error> {
    warn!("apic base msr accessed, read = {}", read);

    let value = gth.apic.msr_apic_base;
    if read {
        write_msr_to_reg(value, vcpu)
    } else {
        if new_value == value {
            warn!("write to apic base msr, but value remains {:x}\n", value);
            Ok(HandleResult::Next)
        } else {
            if unsafe { apic_count } < 10 {
                error!(
                    "os change msr apic-base from {:x} to {:x}",
                    value, new_value
                );
                unsafe {
                    apic_count += 1;
                }
                Ok(HandleResult::Resume)
            } else {
                Err(Error::Unhandled(
                    VMX_REASON_WRMSR,
                    "apic base cannot be changed",
                ))
            }
        }
    }
}

macro_rules! arr {
    ($id: ident $name: ident: [$ty: ty; _] = $value: expr) => {
        $id $name: [$ty; $value.len()] = $value;
    }
}

arr!(static MSR_HANDLERS: [MSRHander; _] = [
    MSRHander(MSR_IA32_APICBASE, emsr_apicbase),
    MSRHander(MSR_IA32_CR_PAT, emsr_pat),
    MSRHander(MSR_MTRRDEF_TYPE, emsr_rdonly),
    MSRHander(MSR_MTRRCAP, emsr_rdonly),
    MSRHander(MSR_IA32_BIOS_SIGN_ID, emsr_rdonly),
    MSRHander(MSR_IA32_MISC_ENABLE, emsr_miscenable),
    MSRHander(MSR_LAPIC_ICR, emsr_unimpl),
    MSRHander(MSR_EFER, emsr_efer),
    MSRHander(MSR_IA32_MCG_CAP, emsr_rdonly),
    MSRHander(MSR_IA32_MCG_STATUS, emsr_rdonly),
    MSRHander(MISC_FEATURE_ENABLES, emsr_gp),
    MSRHander(MSR_PLATFORM_INFO, emsr_platform_info),
]);

pub fn handle_msr_access(
    read: bool,
    vcpu: &VCPU,
    gth: &GuestThread,
) -> Result<HandleResult, Error> {
    let ecx = (vcpu.read_reg(X86Reg::RCX)? & 0xffffffff) as u32;
    let new_value = if !read {
        let rdx = vcpu.read_reg(X86Reg::RDX)?;
        let rax = vcpu.read_reg(X86Reg::RAX)?;
        let v = (rdx << 32) | rax;
        info!("write msr = {:08x}, new_value = {:x}", ecx, v);
        v
    } else {
        info!("read msr = {:08x}", ecx);
        0
    };
    if ecx >= 0x800 && ecx < 0x840 {
        if read {
            let v = gth.apic.read((ecx - 0x800) as usize)?;
            return write_msr_to_reg(v, vcpu);
        } else {
            unimplemented!()
        }
    }
    for handler in MSR_HANDLERS.iter() {
        if handler.0 == ecx {
            return handler.1(ecx, read, new_value, vcpu, gth);
        }
    }
    emsr_unimpl(ecx, read, new_value, vcpu, gth)
}

////////////////////////////////////////////////////////////////////////////////
// VMX_REASON_IO
////////////////////////////////////////////////////////////////////////////////
fn io_size(qual: u64) -> u64 {
    (qual & 0b111) + 1 // Vol.3, table 27-5
}

fn io_in(qual: u64) -> bool {
    (qual >> 3) & 1 == 1
}

// fn io_str_instr(qual: u64) -> bool {
//     (qual >> 4) & 1 == 1
// }
// fn io_rep_prefixed(qual: u64) -> bool {
//     (qual >> 5) & 1 == 1
// }

// fn io_dx(qual: u64) -> bool {
//     qual >> 6 & 1 == 0
// }

fn io_port(qual: u64) -> u16 {
    (qual >> 16 & 0xffff) as u16
}

fn set_all_one(rax: u64, size: u64) -> u64 {
    rax | match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffffffff,
        _ => unreachable!(),
    }
}

fn set_all_zero(rax: u64, size: u64) -> u64 {
    rax & !match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffffffff,
        _ => unreachable!(),
    }
}

fn cfg_address_handler(qual: u64, vcpu: &VCPU, gth: &GuestThread) -> Result<HandleResult, Error> {
    let cf8 = { gth.vm.read().unwrap().cf8 };
    let rax = vcpu.read_reg(X86Reg::RAX)?;
    let size = io_size(qual);
    let port = io_port(qual);
    let offset = cf8_offset(cf8);
    if cf8_bdf(cf8) == 0 {
        trace!(
            "in = {}, rax = {:x}, port = {:x}, offset = {:x}, size = {:x}",
            io_in(qual),
            rax,
            port,
            offset,
            size
        );
    }
    if cf8_enabled(cf8) {
        let bdf = cf8_bdf(cf8);
        if bdf == 0 {
            // only host bridge is supported
            if io_in(qual) {
                let mut v = { gth.vm.read().unwrap().host_bridge_data[offset as usize >> 2] };
                if size == 1 {
                    v >>= (port & 3) * 8;
                } else if size == 2 {
                    v >>= ((port & 2) >> 1) * 16;
                }
                info!(
                    "return size = {}, value = 0x{:0width$x} from port = {:x}",
                    size,
                    v,
                    port,
                    width = size as usize * 2
                );
                vcpu.write_reg(X86Reg::RAX, set_all_zero(rax, size) | v as u64)?;
            } else {
                if size == 4 {
                    gth.vm.write().unwrap().host_bridge_data[offset as usize >> 2] =
                        (rax & 0xffffffff) as u32;
                } else {
                    trace!(
                        "write data {:x} to port={:x}, offset={:x}",
                        rax,
                        port,
                        offset
                    );
                }
            }
        } else {
            if io_in(qual) {
                trace!("bdf = {:x}, return value = all one", bdf,);
                vcpu.write_reg(X86Reg::RAX, set_all_one(rax, size))?;
            }
        }
    } else {
        if io_in(qual) {
            vcpu.write_reg(X86Reg::RAX, set_all_one(rax, size))?;
        }
    }
    Ok(HandleResult::Next)
}

fn cf8_enabled(cf8: u32) -> bool {
    cf8 >> 31 > 0
}

fn cf8_offset(cf8: u32) -> u32 {
    cf8 & 0xff
}

// fn cf8_func(cf8: u32) -> u32 {
//     (cf8 >> 8) & 0b111
// }

// fn cf8_dev(cf8: u32) -> u32 {
//     (cf8 >> 11) & 0b11111
// }

fn cf8_bdf(cf8: u32) -> u16 {
    ((cf8 >> 8) & 0xffff) as u16
}

// fn cf8_bus(cf8: u32) -> u32 {
//     (cf8 >> 16) & 0xff
// }

fn cf8_handler(qual: u64, vcpu: &VCPU, gth: &GuestThread) -> Result<HandleResult, Error> {
    let rax = vcpu.read_reg(X86Reg::RAX)?;
    let size = io_size(qual);
    if size != 4 {
        if io_in(qual) {
            vcpu.write_reg(X86Reg::RAX, set_all_one(rax, size))?;
        }
    }
    if io_in(qual) {
        let cf8_value = gth.vm.read().unwrap().cf8;
        vcpu.write_reg(X86Reg::RAX, set_all_zero(rax, size) | cf8_value as u64)?;
    } else {
        if cf8_bdf(rax as u32) == 0 {
            info!(
                "set cf8 to bdf = {:x}, offset = {:x}",
                cf8_bdf(rax as u32),
                cf8_offset(rax as u32)
            );
        }
        gth.vm.write().unwrap().cf8 = rax as u32;
    }
    Ok(HandleResult::Next)
}

pub fn unknown_port_handler(
    qual: u64,
    vcpu: &VCPU,
    _gth: &GuestThread,
) -> Result<HandleResult, Error> {
    let rax = vcpu.read_reg(X86Reg::RAX)?;
    let port = io_port(qual);
    if io_in(qual) {
        error!("read from io port = {:x}, size = {}", port, io_size(qual));
    } else {
        error!(
            "write to io port = {:x}, rax={:x}, size = {}",
            port,
            rax,
            io_size(qual)
        );
    }
    error!("instruction: {:02x?}", get_vmexit_instr(vcpu));
    Err(Error::Unhandled(VMX_REASON_IO, "unknown port"))
}

const CONFIG_DATA: u16 = 0xcfc;
const CONFIG_DATA3: u16 = 0xcff;
const CONFIG_ADDRESS: u16 = 0xcf8;
const RTC_PORT_REG: u16 = 0x70;
const RTC_PORT_DATA: u16 = 0x71;
const PIT_0: u16 = 0x40;
const PIT_1: u16 = 0x41;
const PIT_2: u16 = 0x42;
const PIT_CMD: u16 = 0x43;

pub fn handle_io(vcpu: &VCPU, gth: &GuestThread) -> Result<HandleResult, Error> {
    let qual = vcpu.read_vmcs(VMCS_RO_EXIT_QUALIFIC)?;
    let rax = vcpu.read_reg(X86Reg::RAX)?;
    let port = io_port(qual);
    // info!(
    //     "io instruction: {:02x?}, rip={:x}",
    //     get_vmexit_instr(vcpu)?,
    //     vcpu.read_reg(X86Reg::RIP)?
    // );
    match port {
        CONFIG_DATA..=CONFIG_DATA3 => cfg_address_handler(qual, vcpu, gth),
        CONFIG_ADDRESS => cf8_handler(qual, vcpu, gth),
        RTC_PORT_REG => {
            if io_in(qual) {
                unimplemented!()
            } else {
                gth.vm.write().unwrap().rtc.reg = rax as u8;
                info!("set CMOS reg to {:x}", rax);
            }
            Ok(HandleResult::Next)
        }
        RTC_PORT_DATA => {
            if io_in(qual) {
                let v = { gth.vm.read().unwrap().rtc.read(RTC_PORT_DATA) };
                info!("return 0x{:x} to port {:x}", v, RTC_PORT_DATA);
                // unimplemented!();
                vcpu.write_reg(X86Reg::RAX, set_all_zero(rax, io_size(qual)) | v as u64)?;
            } else {
                unimplemented!();
            }
            Ok(HandleResult::Next)
        }
        PIT_CMD => {
            if io_in(qual) {
                error!("read from pit command port");
            } else {
                if io_size(qual) == 1 {
                    return pit_cmd_handler(vcpu, gth);
                } else {
                    error!("write more than 1 byte data to pit command port");
                }
            }
            Ok(HandleResult::Next)
        }
        PIT_0 | PIT_1 | PIT_2 => {
            if io_size(qual) != 1 {
                error!("write more than 1 byte to pit data port");
                Ok(HandleResult::Next)
            } else {
                pit_data_handle(vcpu, gth, port, io_in(qual))
            }
        }
        0x61 => {
            if io_in(qual) {
                match io_size(qual) {
                    1 => vcpu.write_reg(X86Reg::RAX, 0b11111111)?,
                    2 => vcpu.write_reg(X86Reg::RAX, 0xffff)?,
                    4 => vcpu.write_reg(X86Reg::RAX, 0xffffffff)?,
                    _ => unreachable!(),
                }
                warn!("return all 1 to unknown port read request, {:x} ", port);
            } else {
                warn!(
                    "silent accept {:b} from port {:x}",
                    vcpu.read_reg(X86Reg::RAX)?,
                    port
                );
            }
            Ok(HandleResult::Next)
        }
        0x21 | 0xa1 => {
            if io_in(qual) {
                warn!("signifying there is no PIC");
                vcpu.write_reg(X86Reg::RAX, rax | 0xff)?;
            } else {
                warn!("just accept {:x} to port {:x}", rax, port);
            };
            Ok(HandleResult::Next)
        }
        0x80 => {
            if io_in(qual) {
                Err((VMX_REASON_IO, "cannot return value to port 0x80"))?
            } else {
                warn!("just accept {:x} to port {:x}", rax, port);
                Ok(HandleResult::Next)
            }
        }
        _ => {
            if io_in(qual) && io_size(qual) == 1 {
                warn!(
                    "silently accept OUT imm8, al, port = {:x}, rax = {:x}",
                    port, rax,
                );
                Ok(HandleResult::Next)
            } else {
                unknown_port_handler(qual, vcpu, gth)
            }
            // warn!("rip = {:x}", vcpu.read_reg(X86Reg::RIP)?);
            // let instruction = get_vmexit_instr(vcpu).unwrap();
            // if instruction[0] == 0xe6 {
            //     if port != 0x80 {
            //         warn!(
            //             "silently accept OUT imm8, al, port = {:x}, rax = {:x}, instr = {:02x?}",
            //             port, rax, instruction
            //         );
            //     }
            //     Ok(HandleResult::Next)
            // } else if instruction == [0xe4, 0x21] {
            //     warn!("signifying there is no PIC");
            //     vcpu.write_reg(X86Reg::RAX, rax | 0xff)?;
            //     Ok(HandleResult::Next)
            // } else {
            //     unknown_port_handler(qual, vcpu, gth)
            // }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// VMX_REASON_VMCALL
////////////////////////////////////////////////////////////////////////////////

extern "C" {
    pub fn print_cstr(s: *const u8, num: u64);
    pub fn print_num(num: u64, format: u64);
}

pub fn default_vmcall_handler(vcpu: &VCPU, _gth: &GuestThread) -> Result<HandleResult, Error> {
    let num = vcpu.read_reg(X86Reg::RDI)?;
    let vmcall_args = vcpu.read_reg(X86Reg::RSI)?;
    match num {
        0 => return Ok(HandleResult::Exit),
        1 => {
            let string = unsafe {
                let ptr = vmcall_args as *const &str;
                ptr.read()
            };
            warn!("{}", string);
        }
        2 => {
            let length = vcpu.read_reg(X86Reg::RDX)?;
            let str_gpa = simulate_paging(vcpu, vmcall_args)?;
            // warn!(
            //     "vmcall 2, rdx, length = {}, rsi args = {:x}",
            //     length, str_gpa
            // );
            unsafe {
                print_cstr(str_gpa as *const u8, length);
            }
        }
        3 => {
            let format = vcpu.read_reg(X86Reg::RDX)?;
            unsafe {
                print_num(vmcall_args, format);
            }
        }
        4 => {
            crate::print_stack(vcpu, 3);
        }
        _ => {}
    };
    Ok(HandleResult::Next)
}

pub fn handle_vmcall(vcpu: &VCPU, gth: &GuestThread) -> Result<HandleResult, Error> {
    let handler = { gth.vm.read().unwrap().vmcall_hander };
    handler(vcpu, gth)
}

////////////////////////////////////////////////////////////////////////////////
// VMX_REASON_EPT_VIOLATION
////////////////////////////////////////////////////////////////////////////////

fn ept_read(qual: u64) -> bool {
    qual & 1 > 0
}

fn ept_write(qual: u64) -> bool {
    qual & 0b10 > 0
}

fn ept_instr_fetch(qual: u64) -> bool {
    qual & 0b100 > 0
}

fn ept_page_walk(qual: u64) -> bool {
    qual & (1 << 7) > 0 && qual & (1 << 8) == 0
}

pub fn handle_ept_violation(
    gpa: usize,
    vcpu: &VCPU,
    gth: &mut GuestThread,
) -> Result<HandleResult, Error> {
    let qual = vcpu.read_vmcs(VMCS_RO_EXIT_QUALIFIC)?;
    if !ept_page_walk(qual) {
        trace!(
            "ept at gpa={:x}, vcpuid = {}, read = {}, write = {}, fetch = {}, page walk = {}, instru = {:02x?}, rsp = {:x}",
            gpa,
            vcpu.id(),
            ept_read(qual),
            ept_write(qual),
            ept_instr_fetch(qual),
            ept_page_walk(qual),
            get_vmexit_instr(vcpu)?,
            vcpu.read_reg(X86Reg::RSP)?
        );
    }
    if gpa >= IO_APIC_BASE && gpa < IO_APIC_BASE + PAGE_SIZE {
        let insn = get_vmexit_instr(vcpu)?;
        emulate_mem_insn(vcpu, gth, &insn, ioapic_access, gpa)?;
        Ok(HandleResult::Next)
    } else if gpa >= APIC_GPA && gpa < APIC_GPA + PAGE_SIZE {
        let insn = get_vmexit_instr(vcpu)?;
        let r = emulate_mem_insn(vcpu, gth, &insn, apic_access, gpa);
        if r.is_err() {
            vcpu.dump()?;
            return Err(r.unwrap_err());
        }
        Ok(HandleResult::Next)
    } else {
        Ok(HandleResult::Resume)
    }
}

////////////////////////////////////////////////////////////////////////////////
// VMX_REASON_XSETBV
////////////////////////////////////////////////////////////////////////////////

pub fn handle_xsetbv(vcpu: &VCPU, gth: &GuestThread) -> Result<HandleResult, Error> {
    if vcpu.read_reg(X86Reg::RCX)? != 0 {
        Err(Error::Unhandled(
            VMX_REASON_XSETBV,
            "only xcr0 is supported",
        ))
    } else {
        let host_xcr0 = { gth.vm.read().unwrap().x86_host_xcr0 };
        let xcr_val =
            (vcpu.read_reg(X86Reg::RDX)? << 32) | (vcpu.read_reg(X86Reg::RAX)? & 0xffffffff);
        if xcr_val & !host_xcr0 != 0 {
            Err(Error::Unhandled(
                VMX_REASON_XSETBV,
                "vm set xcr0 t a superset of default value",
            ))
        } else {
            vcpu.write_reg(X86Reg::XCR0, xcr_val)?;
            info!(
                "default xcr0 = {:x}, write {:x} to guest xcr0",
                host_xcr0, xcr_val
            );
            Ok(HandleResult::Next)
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// VMX_REASON_VMX_TIMER_EXPIRED
////////////////////////////////////////////////////////////////////////////////

pub fn handle_timer_expired(vcpu: &VCPU, gth: &mut GuestThread) -> Result<HandleResult, Error> {
    warn!("firel tiemr interrupt, should set irr");
    gth.apic.fire_timer_interrupt(vcpu);

    Ok(HandleResult::Resume)
}

////////////////////////////////////////////////////////////////////////////////
// VMX_REASON_CPUID
////////////////////////////////////////////////////////////////////////////////
pub const CPUID_STDEXT_FSGSBASE: u32 = 0x00000001;
pub const CPUID_STDEXT_BMI1: u32 = 0x00000008;
pub const CPUID_STDEXT_HLE: u32 = 0x00000010;
pub const CPUID_STDEXT_AVX2: u32 = 0x00000020;
pub const CPUID_STDEXT_BMI2: u32 = 0x00000100;
pub const CPUID_STDEXT_ERMS: u32 = 0x00000200;
pub const CPUID_STDEXT_RTM: u32 = 0x00000800;
pub const CPUID_STDEXT_AVX512F: u32 = 0x00010000;
pub const CPUID_STDEXT_AVX512PF: u32 = 0x04000000;
pub const CPUID_STDEXT_AVX512ER: u32 = 0x08000000;
pub const CPUID_STDEXT_AVX512CD: u32 = 0x10000000;

const CPUID_MONITOR: u32 = 1 << 3;
const CPUID_VMX: u32 = 1 << 5;
const CPUID_SMX: u32 = 1 << 6;
const CPUID_EST: u32 = 1 << 7;
const CPUID_TM2: u32 = 1 << 8;
const CPUID_PDCM: u32 = 1 << 15;
const CPUID_X2APIC: u32 = 1 << 21;
const CPUID_TSC_DL: u32 = 1 << 24;
const CPUID_XSAVE: u32 = 1 << 26;
const CPUID_OSXSAVE: u32 = 1 << 27;
const CPUID_HV: u32 = 1 << 31;

const CPUID_ARAT: u32 = 1 << 2;

const THREADS_PER_CORE: u32 = 1;

//const AMDID2_LAHF: u32 = 0x00000001;
//const AMDID2_CMP: u32 = 0x00000002;
const AMDID2_SVM: u32 = 0x00000004;
// const AMDID2_EXT_APIC: u32 = 0x00000008;
// const AMDID2_CR8: u32 = 0x00000010;
// const AMDID2_ABM: u32 = 0x00000020;
// const AMDID2_SSE4A: u32 = 0x00000040;
// const AMDID2_MAS: u32 = 0x00000080;
// const AMDID2_PREFETCH: u32 = 0x00000100;
const AMDID2_OSVW: u32 = 0x00000200;
const AMDID2_IBS: u32 = 0x00000400;
// const AMDID2_XOP: u32 = 0x00000800;
// const AMDID2_SKINIT: u32 = 0x00001000;
// const AMDID2_WDT: u32 = 0x00002000;
// const AMDID2_LWP: u32 = 0x00008000;
// const AMDID2_FMA4: u32 = 0x00010000;
// const AMDID2_TCE: u32 = 0x00020000;
const AMDID2_NODE_ID: u32 = 0x00080000;
// const AMDID2_TBM: u32 = 0x00200000;
const AMDID2_TOPOLOGY: u32 = 0x00400000;
const AMDID2_PCXC: u32 = 0x00800000;
const AMDID2_PNXC: u32 = 0x01000000;
// const AMDID2_DBE: u32 = 0x04000000;
// const AMDID2_PTSC: u32 = 0x08000000;
const AMDID2_PTSCEL2I: u32 = 0x10000000;
const AMDID_RDTSCP: u32 = 0x08000000;

fn log2(n: u32) -> u32 {
    debug_assert_ne!(n, 0);
    if n.count_ones() == 1 {
        n.trailing_zeros()
    } else {
        32 - n.leading_zeros()
    }
}

pub fn handle_cpuid(vcpu: &VCPU, gth: &GuestThread) -> Result<HandleResult, Error> {
    let eax_in = vcpu.read_reg(X86Reg::RAX).unwrap() as u32;
    let ecx_in = vcpu.read_reg(X86Reg::RCX).unwrap() as u32;
    // FIX ME: can be optimized here
    let (mut eax, mut ebx, mut ecx, mut edx) = do_cpuid(eax_in, ecx_in);
    match eax_in {
        0x1 => {
            /* Set the guest thread id into the apic ID field in CPUID. */
            ebx &= 0x00ffffff;
            ebx |= { gth.vm.read().unwrap().cores | 0xff } << 16;
            ebx |= (gth.id & 0xff) << 24;

            /* Set the hypervisor bit to let the guest know it is
             * virtualized */
            ecx |= CPUID_HV;

            ecx &= !(CPUID_MONITOR
                | CPUID_VMX
                | CPUID_SMX
                | CPUID_EST
                | CPUID_TM2
                | CPUID_PDCM
                | CPUID_TSC_DL);

            if (vmx_read_capability(VMXCap::CPU2)? >> 32) & CPU_BASED2_XSAVES_XRSTORS == 0 {
                ecx &= !CPUID_XSAVE; // unset xsave if it is not supported in cpubased2
                info!("indicate that xsave is not supported");
            }
            if ecx & CPUID_XSAVE == 0 || vcpu.read_reg(X86Reg::CR4)? & X86_CR4_OSXSAVE == 0 {
                ecx &= !CPUID_OSXSAVE; // unset osxsave if it is not supported or it is not turned on
            } else {
                ecx |= CPUID_XSAVE;
            }

            if gth.apic.msr_apic_base & (1 << 10) > 0 {
                ecx |= CPUID_X2APIC;
            } else {
                ecx &= !CPUID_X2APIC;
            }
        }
        0x4 => {
            if eax > 0 || ebx > 0 || ecx > 0 || edx > 0 {
                let cores = { gth.vm.read().unwrap().cores };
                eax &= 0x3ff;
                eax |= (cores - 1) << 26;
                let level = (eax >> 5) & 0x7;
                let logical_cpus = if level >= 3 {
                    THREADS_PER_CORE * cores
                } else {
                    THREADS_PER_CORE
                };
                eax |= (logical_cpus - 1) << 14;
            }
        }
        0x6 => {
            eax = CPUID_ARAT;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        0x7 => {
            // /* Do not advertise TSC_ADJUST */
            // ebx &= !(1 << 1);
            eax = 0;
            ecx = 0;
            edx = 0;
            if ecx_in == 0 {
                ebx = CPUID_STDEXT_FSGSBASE
                    | CPUID_STDEXT_BMI1
                    | CPUID_STDEXT_HLE
                    // | CPUID_STDEXT_AVX2
                    | CPUID_STDEXT_BMI2
                    | CPUID_STDEXT_ERMS
                    | CPUID_STDEXT_RTM
                    | CPUID_STDEXT_AVX512F
                    | CPUID_STDEXT_AVX512PF
                    | CPUID_STDEXT_AVX512ER
                    | CPUID_STDEXT_AVX512CD;
            } else {
                ebx = 0;
            }
        }
        0xa => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        0xb => {
            let logical_cpus;
            let width;
            let level;
            let x2paic_id;
            if ecx_in == 0 {
                logical_cpus = THREADS_PER_CORE;
                width = log2(logical_cpus);
                level = 1; //SMT, Vol2, Table 3-8. Information Returned by CPUID Instruction (Contd.)
                x2paic_id = gth.id;
            } else if ecx_in == 1 {
                logical_cpus = THREADS_PER_CORE * { gth.vm.read().unwrap().cores };
                width = log2(logical_cpus);
                level = 2; // Core
                x2paic_id = gth.id;
            } else {
                logical_cpus = 0;
                width = 0;
                level = 0;
                x2paic_id = 0;
            }
            eax = width & 0x1f;
            ebx = logical_cpus & 0xffff;
            ecx = (level << 8) | (ecx_in & 0xff);
            edx = x2paic_id;
        }
        0xd => {
            if (vmx_read_capability(VMXCap::CPU2)? >> 32) & CPU_BASED2_XSAVES_XRSTORS == 0 {
                eax = 0;
                ebx = 0;
                ecx = 0;
                edx = 0;
            } else {
                unimplemented!("CPUID 0xd unimplemented");
            }
        }
        0x4000_0000 => {
            /* Signal the use of KVM. */
            eax = 0x4000_0000;
            // "KVMKVMKVM\0\0\0"
            // FIX me: temporarily remove this signal
            // ebx = 0x4b4d564b;
            // ecx = 0x564b4d56;
            // edx = 0x4d;
            // ebx = unsafe { std::mem::transmute(*b"hype") };
        }
        0x8000_0001 => {
            /*
             * Hide SVM and Topology Extension features from guest.
             */
            ecx &= !(AMDID2_SVM | AMDID2_TOPOLOGY);

            /*
             * Don't advertise extended performance counter MSRs
             * to the guest.
             */
            ecx &= !(AMDID2_PCXC);
            ecx &= !(AMDID2_PNXC);
            ecx &= !(AMDID2_PTSCEL2I);

            /*
             * Don't advertise Instruction Based Sampling feature.
             */
            ecx &= !(AMDID2_IBS);

            /* NodeID MSR not available */
            ecx &= !(AMDID2_NODE_ID);

            /* Don't advertise the OS visible workaround feature */
            ecx &= !(AMDID2_OSVW);

            /*
             * Hide rdtscp/ia32_tsc_aux until we know how
             * to deal with them.
             */
            edx &= !(AMDID_RDTSCP);
        }
        0x8000_0007 => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 1 << 8; // invariant TSC.
        }
        // 0x40000003 => {
        //     /* Hypervisor Features. */
        //     /* Unset the monitor capability bit so that the guest does not
        //      * try to use monitor/mwait. */
        //     edx &= !(1 << 0);
        // }
        // 0x40000100 => {
        //     /* Signal the use of AKAROS. */
        //     eax = 0;
        //     // "AKAROSINSIDE"
        //     ebx = 0x52414b41;
        //     ecx = 0x4e49534f;
        //     edx = 0x45444953;
        // }
        // /* Hypervisor Features. */
        // 0x40000103 => {
        //     /* Unset the monitor capability bit so that the guest does not
        //      * try to use monitor/mwait. */
        //     edx &= !(1 << 0);
        // }
        _ => {}
    }
    vcpu.write_reg(X86Reg::RAX, eax as u64).unwrap();
    vcpu.write_reg(X86Reg::RBX, ebx as u64).unwrap();
    vcpu.write_reg(X86Reg::RCX, ecx as u64).unwrap();
    vcpu.write_reg(X86Reg::RDX, edx as u64).unwrap();
    trace!(
        "cpuid, eax_in={:x}, ecx_in={:x}, eax={:x}, ebx={:x}, ecx={:x}, edx={:x}",
        eax_in,
        ecx_in,
        eax,
        ebx,
        ecx,
        edx
    );
    Ok(HandleResult::Next)
}

#[cfg(test)]
mod test {
    use super::log2;
    #[test]
    fn test_log2() {
        for i in 1..10 {
            println!("log2({}) = {}", i, log2(i));
        }
    }

    use super::{get_bus_frequency, get_tsc_frequency};
    #[test]
    fn test_sysctl() {
        println!("tsc f = {}", get_bus_frequency());
        println!("bus f = {}", get_tsc_frequency());
        // let b = sysctl_u64("hw.busfrequency");
        // println!("but f = {}", b);
    }
}
