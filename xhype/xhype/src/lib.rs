/* SPDX-License-Identifier: GPL-2.0-only */
#![allow(unused_imports)]
// #![allow(dead_code)]
// #![allow(unused_variables)]
#![allow(non_upper_case_globals)]
#![cfg_attr(feature = "vthread_closure", feature(fn_traits))]
mod apic;
#[allow(dead_code)]
mod bios;
#[allow(non_upper_case_globals)]
pub mod consts;
mod cpuid;
mod decode;
pub mod err;
#[allow(dead_code)]
mod hv;
mod ioapic;
#[allow(dead_code)]
pub mod linux;
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod mach;
mod pit;
mod rtc;
mod serial;
pub mod utils;

use utils::mach_abs_time_ns;
#[allow(dead_code)]
pub mod virtio;
mod vmexit;
pub mod vthread;
#[allow(dead_code)]
mod x86;
use crate::consts::*;
use crate::rtc::Rtc;
use apic::Apic;
#[allow(unused_imports)]
use consts::msr::*;
use cpuid::do_cpuid;
use err::Error;
use hv::vmx::*;
use hv::X86Reg;
use hv::{
    interrupt_vcpu, MemSpace, DEFAULT_MEM_SPACE, HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE,
    VCPU,
};
use ioapic::IoApic;
#[allow(unused_imports)]
use log::*;
use mach::{vm_self_region, MachVMBlock};
use pit::Pit;
use serial::Serial;
use std::cell::Cell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use virtio::{VirtioId, VirtioMmioDev, VirtioVqDev};
use vmexit::*;
use x86::*;

fn print_stack_inner(vcpu: &VCPU, depth: i32) -> Result<(), Error> {
    let rip = vcpu.read_reg(X86Reg::RIP)?;
    warn!(
        "current rip = {:x}, rbp = {:x}",
        rip,
        vcpu.read_reg(X86Reg::RBP)?
    );
    let mut rbp = vcpu.read_reg(X86Reg::RBP)?;
    for i in 0..depth {
        let rbp_physical = simulate_paging(vcpu, rbp)?;
        let return_address_physical = simulate_paging(vcpu, rbp + 8)?;
        error!(
            "i = {}, rbp = {:x}, rip = {:x}",
            i,
            rbp,
            read_host_mem::<usize>(return_address_physical, 0)
        );
        rbp = read_host_mem::<u64>(rbp_physical, 0);
    }
    Ok(())
}

pub fn print_stack(vcpu: &VCPU, depth: i32) {
    match print_stack_inner(vcpu, depth) {
        Ok(_) => (),
        Err(e) => error!("error happens in print_stack(): {:?}", e),
    }
}

////////////////////////////////////////////////////////////////////////////////
// VMManager
////////////////////////////////////////////////////////////////////////////////

// only one vmm is allowed to be created per process
pub struct VMManager {
    marker: PhantomData<()>, // add a PhantomData here to prevent user from constructing VMM by VMManager{}
    x86_host_xcr0: u64,
}

impl VMManager {
    pub fn new() -> Result<Self, Error> {
        hv::vm_create(0)?;
        let (eax, _, _, edx) = do_cpuid(0xd, 0x0);
        let proc_supported_features = (edx as u64) << 32 | (eax as u64);
        Ok(VMManager {
            marker: PhantomData,
            x86_host_xcr0: proc_supported_features & X86_MAX_XCR0,
        })
    }

    pub fn create_vm(&self, cores: u32) -> Result<VirtualMachine, Error> {
        assert_eq!(cores, 1); //FIXME: currently only one core is supported
        VirtualMachine::new(cores, &self)
    }
}

// let rust call hv_vm_destroy automatically
impl Drop for VMManager {
    fn drop(&mut self) {
        hv::vm_destroy().unwrap();
    }
}

////////////////////////////////////////////////////////////////////////////////
// VirtualMachine
////////////////////////////////////////////////////////////////////////////////
// pub fn poke_guest(a: u8, b: u32) {
//     println!("pock");
// }
/// A VirtualMachine is the physical hardware seen by a guest, including physical
/// memory, number of cpu cores, etc.
pub struct VirtualMachine {
    mem_space: RwLock<MemSpace>,
    cores: u32,
    // fixme: add lock to pci ports?
    pub(crate) cf8: RwLock<u32>,
    pub(crate) host_bridge_data: RwLock<[u32; 16]>,
    pub(crate) ioapic: Arc<RwLock<IoApic>>,
    pub(crate) vcpu_ids: Arc<RwLock<Vec<u32>>>,
    /// the memory that is specifically allocated for the guest. For a vthread,
    /// it contains its stack and a paging structure. For a kernel, it contains
    /// its bios tables, APIC pages, high memory, etc.
    /// guest virtual address -> host VM block
    pub(crate) guest_mmap: RwLock<HashMap<usize, MachVMBlock>>,
    pub vmcall_hander: fn(&VCPU, &GuestThread) -> Result<HandleResult, Error>,
    x86_host_xcr0: u64,
    pub(crate) rtc: RwLock<Rtc>,
    pub(crate) pit: RwLock<Pit>,
    pub(crate) com1: RwLock<Serial>,
    pub(crate) com2: RwLock<Serial>,
    pub(crate) virtio_mmio_dev: Vec<Mutex<VirtioMmioDev>>,
    pub(crate) intr_senders: Arc<Mutex<Option<Vec<Sender<u8>>>>>,
}

impl VirtualMachine {
    // make it private to force user to create a vm by calling create_vm to make
    // sure that hv_vm_create() is called before hv_vm_space_create() is called

    fn ioapic_loop(
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
            let senders = intr_senders.lock().unwrap();
            if let Some(ref some_senders) = *senders {
                some_senders[0].send((entry & 0xff) as u8).unwrap();
                interrupt_vcpu(&vcpu_ids[0..1]).unwrap();
            }
            // println!("get irq = {}", irq);
            // println!("data in io apic = {:x}", entry);
            // println!("ioapic data = {:?}", &ioapic.value[0..32]);
        }
    }

    fn new(cores: u32, vmm: &VMManager) -> Result<Self, Error> {
        let mut host_bridge_data = [0; 16];
        let data = [0x71908086, 0x02000006, 0x06000001]; //0:00.0 Host bridge: Intel Corporation 440BX/ZX/DX - 82443BX/ZX/DX Host bridge (rev 01)
        for (i, n) in data.iter().enumerate() {
            host_bridge_data[i] = *n;
        }
        let (irq_sender, irq_receiver) = channel::<u32>();

        let irq = 0;
        let virtio_start: usize = 64 * GiB;
        // let vqdev = VirtioVqDev::new_console("console".to_string(), irq_sender.clone());
        // let console = VirtioMmioDev::new(virtio_start, irq, vqdev, poke_guest);
        let console = VirtioMmioDev::new_console(virtio_start, irq, "console".into(), irq_sender);
        let ioapic = Arc::new(RwLock::new(IoApic::new()));
        let vcpu_ids = Arc::new(RwLock::new(vec![u32::MAX; cores as usize]));
        let intr_senders = Arc::new(Mutex::new(None));
        let mut vm = VirtualMachine {
            mem_space: RwLock::new(MemSpace::create()?),
            cores,
            cf8: RwLock::new(0),
            host_bridge_data: RwLock::new(host_bridge_data),
            ioapic: ioapic.clone(),
            vcpu_ids: vcpu_ids.clone(),
            guest_mmap: RwLock::new(HashMap::new()),
            vmcall_hander: default_vmcall_handler,
            x86_host_xcr0: vmm.x86_host_xcr0,
            rtc: RwLock::new(Rtc { reg: 0 }),
            pit: RwLock::new(Pit::default()),
            com1: RwLock::new(Serial::default()),
            com2: RwLock::new(Serial::default()),
            virtio_mmio_dev: vec![Mutex::new(console)],
            intr_senders: intr_senders.clone(),
        };
        vm.gpa2hva_map()?;
        std::thread::Builder::new()
            .name("ioapic".into())
            .spawn(move || {
                Self::ioapic_loop(
                    intr_senders.clone(),
                    irq_receiver,
                    ioapic.clone(),
                    vcpu_ids.clone(),
                )
            })
            .expect("cannot create ioapic thread");
        Ok(vm)
    }

    fn map_guest_mem(&self, maps: HashMap<usize, MachVMBlock>) -> Result<(), Error> {
        let mut mem_space = self.mem_space.write().unwrap();
        for (gpa, mem_block) in maps.iter() {
            info!(
                "map gpa={:x} to hva={:x}, size={}page",
                gpa,
                mem_block.start,
                mem_block.size / 4096
            );
            mem_space.map(
                mem_block.start,
                *gpa,
                mem_block.size,
                HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
            )?;
        }
        *self.guest_mmap.write().unwrap() = maps;
        Ok(())
    }

    fn gpa2hva_map(&mut self) -> Result<(), Error> {
        let mut trial_addr = 1;
        let mut mem_space = self.mem_space.write().unwrap();
        loop {
            match vm_self_region(trial_addr) {
                Ok((start, size, info)) => {
                    if info.protection > 0 {
                        mem_space.map(start, start, size, info.protection as u64)?;
                    }
                    trial_addr = start + size;
                }
                Err(_) => {
                    break;
                }
            }
        }
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
// GuestThread
////////////////////////////////////////////////////////////////////////////////

pub struct GuestThread {
    pub vm: Arc<VirtualMachine>,
    pub id: u32,
    pub init_vmcs: HashMap<u32, u64>,
    pub init_regs: HashMap<X86Reg, u64>,
    vapic_addr: usize,
    posted_irq_desc: usize,
    pub(crate) msr_pat: Cell<u64>,
    pub(crate) apic: Apic,
    pub(crate) intr_receiver: Option<Receiver<u8>>,
}

impl GuestThread {
    pub fn new(vm: &Arc<VirtualMachine>, id: u32) -> Self {
        GuestThread {
            vm: Arc::clone(vm),
            id: id,
            init_vmcs: HashMap::new(),
            init_regs: HashMap::new(),
            vapic_addr: 0,
            posted_irq_desc: 0,
            msr_pat: Cell::new(0x7040600070406),
            apic: Apic::new(APIC_GPA as u64, true, false, id, id == 0),
            intr_receiver: None,
        }
    }

    pub fn start(mut self) -> std::thread::JoinHandle<Result<(), Error>> {
        std::thread::spawn(move || {
            let vcpu = VCPU::create()?;
            {
                self.vm.vcpu_ids.write().unwrap()[self.id as usize] = vcpu.id();
            }
            self.run_on(&vcpu)
        })
    }
    pub(crate) fn run_on(&mut self, vcpu: &VCPU) -> Result<(), Error> {
        {
            let mem_space = &self.vm.mem_space.read().unwrap();
            vcpu.set_space(mem_space)?;
            trace!("set vcpu {} space to {}", vcpu.id(), mem_space.id);
        }
        let result = self.run_on_inner(vcpu);
        if result.is_err() {
            error!("last rip = {:x}", vcpu.read_reg(X86Reg::RIP)?);
            print_stack(vcpu, 4);
        }
        vcpu.set_space(&DEFAULT_MEM_SPACE)?;
        trace!("set vcpu back {} space to 0", vcpu.id());
        result
    }

    fn run_on_inner(&mut self, vcpu: &VCPU) -> Result<(), Error> {
        // it looks like Hypervisor.framework does not support APIC virtualization
        // vcpu.set_vapic_address(self.vapic_addr)?;
        vcpu.enable_msrs()?;
        vcpu.long_mode()?;
        for (field, value) in self.init_vmcs.iter() {
            vcpu.write_vmcs(*field, *value)?;
        }
        for (reg, value) in self.init_regs.iter() {
            vcpu.write_reg(*reg, *value)?;
        }

        // vcpu.dump().unwrap();
        let mut result: HandleResult;
        let mut last_physical_addr: Option<u64> = None;
        let mut ept_count = 0;
        let mut irq_count = 0;
        loop {
            if let Some(deadline) = self.apic.next_timer_ns {
                vcpu.run_until(deadline)?;
            } else {
                // vcpu.run()?;
                vcpu.run_until(u64::MAX)?;
            }
            let reason = vcpu.read_vmcs(VMCS_RO_EXIT_REASON)?;
            // let rip = vcpu.read_reg(X86Reg::RIP)?;
            if reason != VMX_REASON_EPT_VIOLATION
                && reason != VMX_REASON_IRQ
                && reason != VMX_REASON_VMX_TIMER_EXPIRED
            {
                // warn!("vm exit reason = {}, rip = {:x}", reason, rip);
            }
            let instr_len = vcpu.read_vmcs(VMCS_RO_VMEXIT_INSTR_LEN)?;
            if reason != VMX_REASON_IRQ {
                irq_count = 0;
            } else {
                irq_count += 1;
            }
            if irq_count > 1000 {
                error!(
                    "instr = {:02x?}， rip = {:x}",
                    get_vmexit_instr_more(vcpu, 32, 32)?,
                    vcpu.read_reg(X86Reg::RIP)?
                );
                return Err((VMX_REASON_IRQ, "irq for too many times"))?;
            }
            result = match reason {
                VMX_REASON_EXC_NMI => {
                    let info = vcpu.read_vmcs(VMCS_RO_VMEXIT_IRQ_INFO)?;
                    let code = vcpu.read_vmcs(VMCS_RO_VMEXIT_IRQ_ERROR)?;
                    let valid = (info >> 31) & 1 == 1;
                    let nmi = (info >> 12) & 1 == 1;
                    let e_type = (info >> 8) & 0b111;
                    let vector = info & 0xf;
                    warn!(
                        "VMX_REASON_EXC_NMI, valid = {}, nmi = {}, type = {}, vector = {}, code = {:b}",
                        valid, nmi, e_type, vector, code
                    );
                    if vector == 6 {
                        warn!(
                            "invalid opcode: {:02x?}, rip = {:x}",
                            get_vmexit_instr(vcpu)?,
                            vcpu.read_reg(X86Reg::RIP)?
                        );
                    }
                    return Err(Error::Unhandled(reason, "unhandled exception"));
                }
                VMX_REASON_IRQ => {
                    let info = vcpu.read_vmcs(VMCS_RO_VMEXIT_IRQ_INFO)?;
                    let code = vcpu.read_vmcs(VMCS_RO_VMEXIT_IRQ_ERROR)?;
                    let valid = (info >> 31) & 1 == 1;
                    let nmi = (info >> 12) & 1 == 1;
                    let e_type = (info >> 8) & 0b111;
                    let vector = info & 0xf;
                    error!(
                        "VMX_REASON_IRQ, valid = {}, nmi = {}, type = {}, vector = {}, code = {:b}",
                        valid, nmi, e_type, vector, code
                    );
                    print_stack(vcpu, 10);
                    if let Some(ref recv) = self.intr_receiver {
                        if let Ok(vector) = recv.try_recv() {
                            // println!("get interrupt vector {}", vector);
                            self.apic.fire_externel_interrupt(vector);
                            HandleResult::Resume
                        } else {
                            HandleResult::Exit
                        }
                    } else {
                        HandleResult::Exit
                    }
                    // if valid {
                    //     HandleResult::Exit
                    // } else {
                    //     // error!(
                    //     //     "VMX_REASON_EXC_NMI, valid = {}, nmi = {}, type = {}, vector = {}, code = {:b}",
                    //     //     valid, nmi, e_type, vector, code
                    //     // );
                    //     HandleResult::Exit
                    // }
                }
                VMX_REASON_IRQ_WND => {
                    debug_assert_eq!(vcpu.read_reg(X86Reg::RFLAGS)? & FL_IF, FL_IF);
                    let mut ctrl_cpu = vcpu.read_vmcs(VMCS_CTRL_CPU_BASED)?;
                    ctrl_cpu &= !CPU_BASED_IRQ_WND;
                    vcpu.write_vmcs(VMCS_CTRL_CPU_BASED, ctrl_cpu)?;
                    // warn!("interrupt window");
                    HandleResult::Resume
                }
                VMX_REASON_CPUID => handle_cpuid(&vcpu, self)?,
                VMX_REASON_HLT => HandleResult::Exit,
                VMX_REASON_VMCALL => handle_vmcall(&vcpu, self)?,
                VMX_REASON_MOV_CR => handle_cr(&vcpu, self)?,
                VMX_REASON_IO => handle_io(&vcpu, self)?,
                VMX_REASON_RDMSR => handle_msr_access(true, &vcpu, self)?,
                VMX_REASON_WRMSR => handle_msr_access(false, &vcpu, self)?,
                VMX_REASON_EPT_VIOLATION => {
                    let physical_addr = vcpu.read_vmcs(VMCS_GUEST_PHYSICAL_ADDRESS)?;
                    let r = handle_ept_violation(physical_addr as usize, vcpu, self);
                    match r {
                        Err(e) => return Err(e),
                        Ok(HandleResult::Resume) => {
                            if last_physical_addr == Some(physical_addr) {
                                ept_count += 1;
                            } else {
                                ept_count = 1;
                                last_physical_addr = Some(physical_addr);
                            }
                            if ept_count > 10 {
                                error!(
                                    "EPT violation at {:x} for {} times",
                                    last_physical_addr.unwrap(),
                                    ept_count
                                );
                                print_stack(vcpu, 10);
                                return Err(Error::Unhandled(
                                    reason,
                                    "too many EPT faults at the same address",
                                ));
                            } else {
                                HandleResult::Resume
                            }
                        }
                        Ok(v) => {
                            ept_count = 0;
                            last_physical_addr = None;
                            v
                        }
                    }
                }
                VMX_REASON_XSETBV => handle_xsetbv(&vcpu, self)?,
                VMX_REASON_VMX_TIMER_EXPIRED => {
                    // timer expiration should only happen when we set the timer.
                    debug_assert!(self.apic.next_timer_ns.is_some());
                    handle_timer_expired(&vcpu, self)?
                }
                _ => {
                    info!("Unhandled reason = {}", reason);
                    if reason < VMX_REASON_MAX {
                        return Err(Error::Unhandled(reason, "unable to handle"));
                    } else {
                        return Err(Error::Unhandled(reason, "unknown reason"));
                    }
                }
            };
            match result {
                HandleResult::Exit => break,
                HandleResult::Next => {
                    let rip = vcpu.read_reg(X86Reg::RIP)?;
                    vcpu.write_reg(X86Reg::RIP, rip + instr_len)?;
                }
                HandleResult::Resume => (),
            };
            if result == HandleResult::Next {
                let mut irq_ignore = vcpu.read_vmcs(VMCS_GUEST_IGNORE_IRQ)?;
                if irq_ignore & 0b11 != 0 {
                    irq_ignore &= !0b11;
                    vcpu.write_vmcs(VMCS_GUEST_IGNORE_IRQ, irq_ignore)?;
                }
            }
            let vector = self.apic.inject_interrupt(vcpu)?;
            if reason == VMX_REASON_IRQ {
                warn!("injected vector {}", vector);
            }
        }
        Ok(())
    }
}

extern "C" {
    pub fn hlt();
    pub fn raw_vmcall(num: u64, args: *const u8, length: u64);
}

/// num is the function number, args is a pointer to arguments
/// currently the following functions are supported:
/// num = 1, args = pointer to a c-style string: print the string
pub fn vmcall(num: u64, args: *const u8) {
    unsafe {
        raw_vmcall(num, args, 0);
    }
}

pub fn vmcall2(num: u64, args: *const u8, length: u64) {
    unsafe {
        raw_vmcall(num, args, length);
    }
}
