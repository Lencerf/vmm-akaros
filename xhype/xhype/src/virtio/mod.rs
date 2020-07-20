pub mod console;
mod virtq;

use crate::hv::interrupt_vcpu;
use crate::print_cstr;
use crate::print_stack;
use crate::{read_host_mem, write_host_mem};
use crate::{Error, GuestThread, VCPU};
#[allow(unused_imports)]
use log::*;
use std::io::stdin;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use virtq::*;

////////////////////////////////////////////////////////////////////////////////
// const
////////////////////////////////////////////////////////////////////////////////

/*
 * Control registers
 */

/* Magic value ("virt" string) - Read Only */
pub const VIRTIO_MMIO_MAGIC_VALUE: usize = 0x000;

/* Virtio device version - Read Only */
pub const VIRTIO_MMIO_VERSION: usize = 0x004;

/* Virtio device ID - Read Only */
pub const VIRTIO_MMIO_DEVICE_ID: usize = 0x008;

/* Virtio vendor ID - Read Only */
pub const VIRTIO_MMIO_VENDOR_ID: usize = 0x00c;

/* Bitmask of the features supported by the device (host)
 * (32 bits per set) - Read Only */
pub const VIRTIO_MMIO_DEVICE_FEATURES: usize = 0x010;

/* Device (host) features set selector - Write Only */
pub const VIRTIO_MMIO_DEVICE_FEATURES_SEL: usize = 0x014;

/* Bitmask of features activated by the driver (guest)
 * (32 bits per set) - Write Only */
pub const VIRTIO_MMIO_DRIVER_FEATURES: usize = 0x020;

/* Activated features set selector - Write Only */
pub const VIRTIO_MMIO_DRIVER_FEATURES_SEL: usize = 0x024;

/* Guest's memory page size in bytes - Write Only */
#[cfg(feature = "virtio_mmio_legacy")]
pub const VIRTIO_MMIO_GUEST_PAGE_SIZE: usize = 0x028;

/* Queue selector - Write Only */
pub const VIRTIO_MMIO_QUEUE_SEL: usize = 0x030;

/* Maximum size of the currently selected queue - Read Only */
pub const VIRTIO_MMIO_QUEUE_NUM_MAX: usize = 0x034;

/* Queue size for the currently selected queue - Write Only */
pub const VIRTIO_MMIO_QUEUE_NUM: usize = 0x038;

/* Used Ring alignment for the currently selected queue - Write Only */
#[cfg(feature = "virtio_mmio_legacy")]
pub const VIRTIO_MMIO_QUEUE_ALIGN: usize = 0x03c;

/* Guest's PFN for the currently selected queue - Read Write */
#[cfg(feature = "virtio_mmio_legacy")]
pub const VIRTIO_MMIO_QUEUE_PFN: usize = 0x040;

/* Ready bit for the currently selected queue - Read Write */
pub const VIRTIO_MMIO_QUEUE_READY: usize = 0x044;

/* Queue notifier - Write Only */
pub const VIRTIO_MMIO_QUEUE_NOTIFY: usize = 0x050;

/* Interrupt status - Read Only */
pub const VIRTIO_MMIO_INTERRUPT_STATUS: usize = 0x060;

/* Interrupt acknowledge - Write Only */
pub const VIRTIO_MMIO_INTERRUPT_ACK: usize = 0x064;

/* Device status register - Read Write */
pub const VIRTIO_MMIO_STATUS: usize = 0x070;

/* Selected queue's Descriptor Table address, 64 bits in two halves */
pub const VIRTIO_MMIO_QUEUE_DESC_LOW: usize = 0x080;
pub const VIRTIO_MMIO_QUEUE_DESC_HIGH: usize = 0x084;

/* Selected queue's Available Ring address, 64 bits in two halves */
pub const VIRTIO_MMIO_QUEUE_AVAIL_LOW: usize = 0x090;
pub const VIRTIO_MMIO_QUEUE_AVAIL_HIGH: usize = 0x094;

/* Selected queue's Used Ring address, 64 bits in two halves */
pub const VIRTIO_MMIO_QUEUE_USED_LOW: usize = 0x0a0;
pub const VIRTIO_MMIO_QUEUE_USED_HIGH: usize = 0x0a4;

/* Configuration atomicity value */
pub const VIRTIO_MMIO_CONFIG_GENERATION: usize = 0x0fc;

/* The config space is defined by each driver as
 * the per-driver configuration space - Read Write */
pub const VIRTIO_MMIO_CONFIG: usize = 0x100;

////////////////////////////////////////////////////////////////////////////////
// struct
////////////////////////////////////////////////////////////////////////////////

/* This marks a buffer as continuing via the next field. */
pub const VRING_DESC_F_NEXT: u16 = 1;
/* This marks a buffer as write-only (otherwise read-only). */
pub const VRING_DESC_F_WRITE: u16 = 2;
/* This means the buffer contains a list of buffer descriptors. */
pub const VRING_DESC_F_INDIRECT: u16 = 4;

/* The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers. */
pub const VRING_USED_F_NO_NOTIFY: u16 = 1;
/* The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.  */
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;

/* We support indirect buffer descriptors */
pub const VIRTIO_RING_F_INDIRECT_DESC: u16 = 28;

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
pub const VIRTIO_RING_F_EVENT_IDX: u16 = 29;

pub const VIRTIO_MMIO_INT_VRING: u32 = 1 << 0;
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 1 << 1;

type AvailIndexSender = Sender<Option<u16>>;
type AvailIndexReceiver = Receiver<Option<u16>>;
type VirtioVqSrv = fn(u32, AvailIndexReceiver, Receiver<Virtq>, Sender<u32>, Arc<RwLock<u32>>);

struct VirtioVq {
    name: String,
    qnum_max: u32,
    qready: u32,
    last_avail: u16,
    virtq: Virtq,
    srv: VirtioVqSrv,
    index_sender: AvailIndexSender, // (index, irq, vcpuid)
    virtq_sender: Sender<Virtq>,
}

impl VirtioVq {
    pub fn new(
        name: String,
        qnum_max: u32,
        srv: VirtioVqSrv,
        irq: u32,
        irq_sender: Sender<u32>,
        isr: Arc<RwLock<u32>>,
    ) -> Self {
        let (index_sender, index_receiver) = channel();
        let (virtq_sender, virtq_receiver) = channel();
        std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || srv(irq, index_receiver, virtq_receiver, irq_sender, isr))
            .expect(&format!("cannot create thread for virtq {}", &name));
        VirtioVq {
            name,
            qnum_max,
            qready: 0,
            last_avail: 0,
            virtq: Virtq::new(0),
            srv,
            index_sender,
            virtq_sender,
        }
    }
}

// virtio-v1.0-cs04 s4 Device types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioId {
    Reserved = 0,
    Net = 1,
    Block = 2,
    Console = 3,
    Entropy = 4,
    BalloonTraditional = 5,
    IoMemory = 6,
    RpMsg = 7,
    ScsiHost = 8,
    Transport9P = 9, // 9P transport
    Mac80211Wlan = 10,
    RProcSerial = 11,
    Caif = 12,
    Balloon = 13,
    GPU = 16,
    Timer = 17,
    Input = 18,
}

pub struct VirtioVqDev {
    name: String,
    dev_id: VirtioId,
    dev_feat: u64,
    dri_feat: u64,
    cfg: Vec<u32>,
    cfg_d: Vec<u32>,
    vqs: Vec<VirtioVq>,
}

fn virtio_validate_feat(vqdev: &VirtioVqDev, feat: u64) -> Result<(), &'static str> {
    match vqdev.dev_id {
        VirtioId::Console | VirtioId::Net | VirtioId::Block => {}
        VirtioId::Reserved => return Err("reserved device"),
        _ => return Err("not implemented"),
    }
    if feat & (1 << VIRTIO_F_VERSION_1) == 0 {
        return Err("A device must offer the VIRTIO_F_VERSION_1 feature bit");
    }
    Ok(())
}

impl VirtioVqDev {
    pub fn verify_feat(&self) -> Result<(), &'static str> {
        match self.dev_id {
            VirtioId::Console => {}
            // VirtioId::Reserved => return Err("reserved device"),
            _ => return Err("not implemented"),
        };
        if self.dri_feat & (1 << VIRTIO_F_VERSION_1) == 0 {
            return Err("A driver must accept the VIRTIO_F_VERSION_1 feature bit");
        }
        error!(
            "driver feat = {:x}, dev feat = {:x}",
            self.dri_feat, self.dev_feat
        );
        if self.dri_feat & !self.dev_feat != 0 {
            return Err("driver activated features that are not supported by the device");
        }
        Ok(())
    }
}

pub struct VirtioMmioDev {
    addr: usize,
    dev_feat_sel: u32,
    dri_feat_sel: u32,
    qsel: u32,             //
    isr: Arc<RwLock<u32>>, // interrupt status
    status: u8,
    cfg_gen: u32,
    vqdev: VirtioVqDev,
    pub irq: u32,
}
////////////////////////////////////////////////////////////////////////////////
// config
////////////////////////////////////////////////////////////////////////////////
pub const VIRTIO_CONFIG_S_ACKNOWLEDGE: u8 = 1;
/* We have found a driver for the device. */
pub const VIRTIO_CONFIG_S_DRIVER: u8 = 2;
/* Driver has used its parts of the config, and is happy */
pub const VIRTIO_CONFIG_S_DRIVER_OK: u8 = 4;
/* Driver has finished configuring features */
pub const VIRTIO_CONFIG_S_FEATURES_OK: u8 = 8;
/* Device entered invalid state, driver must reset it */
pub const VIRTIO_CONFIG_S_NEEDS_RESET: u8 = 0x40;
/* We've given up on this device. */
pub const VIRTIO_CONFIG_S_FAILED: u8 = 0x80;

/* Some virtio feature bits (currently bits 28 through 32) are reserved for the
 * transport being used (eg. virtio_ring), the rest are per-device feature
 * bits. */
pub const VIRTIO_TRANSPORT_F_START: u8 = 28;
pub const VIRTIO_TRANSPORT_F_END: u8 = 33;

/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#[cfg(feature = "virtio_mmio_legacy")]
pub const VIRTIO_F_NOTIFY_ON_EMPTY: u8 = 24;

/* Can the device handle any descriptor layout? */
#[cfg(feature = "virtio_mmio_legacy")]
pub const VIRTIO_F_ANY_LAYOUT: u8 = 27;

/* v1.0 compliant. */
pub const VIRTIO_F_VERSION_1: u8 = 32;
pub const VIRTIO_F_NOTIFICATION_DATA: u8 = 38;

////////////////////////////////////////////////////////////////////////////////
// mmio
////////////////////////////////////////////////////////////////////////////////

pub const VIRT_MAGIC: u32 = 0x74726976; /* 'virt' */

pub const VIRT_MMIO_VERSION: u32 = 0x2;

pub const VIRT_MMIO_VENDOR: u32 = 0x52414B41; /* 'AKAR' */

fn device_reset(dev: &mut VirtioMmioDev) {
    dev.vqdev.dri_feat = 0;
    dev.status = 0;
    *dev.isr.write().unwrap() = 0;
    for vq in dev.vqdev.vqs.iter_mut() {
        vq.qready = 0;
        vq.last_avail = 0;
    }
    dev.vqdev.cfg.clone_from(&dev.vqdev.cfg_d);
    dev.cfg_gen += 1;
}

fn virtio_mmio_read(dev: &VirtioMmioDev, gpa: usize, size: u8) -> u32 {
    let mask: u32 = match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffffffff,
        _ => unreachable!(),
    };
    let offset = gpa - dev.addr as usize;

    // Return 0 for all registers except the magic number,
    // the mmio version, and the device vendor when either
    // there is no vqs on the vqdev.
    if dev.vqdev.vqs.len() == 0 {
        return match offset {
            VIRTIO_MMIO_MAGIC_VALUE => VIRT_MAGIC,
            VIRTIO_MMIO_VERSION => VIRT_MMIO_VERSION,
            VIRTIO_MMIO_VENDOR_ID => VIRT_MMIO_VENDOR,
            _ => 0,
        } & mask;
    }

    // virtio-v1.0-cs04 s4.2.3.1.1 Device Initialization (MMIO section)
    if dev.vqdev.dev_id == VirtioId::Reserved
        && offset != VIRTIO_MMIO_MAGIC_VALUE
        && offset != VIRTIO_MMIO_VERSION
        && offset != VIRTIO_MMIO_DEVICE_ID
    {
        error!(
            "Attempt to read from a register not MagicValue, Version, or \
        DeviceID on a device whose DeviceID is 0x0, See virtio-v1.0-cs04 \
        s4.2.3.1.1 Device Initialization"
        );
    }

    // Now we know that the host provided a vqdev. As soon as the driver
    // tries to read the magic number, we know it's considering the device.
    // This is a great time to validate the features the host is providing.
    // The host must provide a valid combination of features, or we crash
    // here until the offered feature combination is made valid.
    if offset == VIRTIO_MMIO_MAGIC_VALUE {
        // validate features
        if let Err(e) = virtio_validate_feat(&dev.vqdev, dev.vqdev.dev_feat) {
            error!("Virtio validate feat error: {}", e);
        }
    }

    // Warn if FAILED status bit is set.
    // virtio-v1.0-cs04 s2.1.1 Device Status Field
    if dev.status & VIRTIO_CONFIG_S_FAILED > 0 {
        warn!(
            "The FAILED status bit is set. The driver should probably reset \
        the device before continuing."
        );
    }

    if offset >= VIRTIO_MMIO_CONFIG {
        let offset = offset - VIRTIO_MMIO_CONFIG;
        if dev.vqdev.cfg.len() == 0 {
            error!(
                "Driver attempted to read the device-specific configuration \
             space, but the device failed to provide it."
            );
        }

        // virtio-v1.0-cs04 s3.1.1 Device Initialization
        if dev.status & VIRTIO_CONFIG_S_DRIVER == 0 {
            error!(
                "Driver attempted to read the device-specific configuration \
            space before setting the DRIVER status bit. See virtio-v1.0-cs04 \
            s3.1.1 Device Initialization"
            );
        }

        if offset + (size as usize) > (dev.vqdev.cfg.len() << 2)
            || offset > usize::max_value() - (size as usize)
        {
            error!(
                "Attempt to read invalid offset of the device specific \
            configuration space, or (offset + read width) wrapped around."
            );
        }
        let value = dev.vqdev.cfg[offset >> 2];
        return (value >> (offset & 0b11)) & mask;
    }

    // virtio-v1.0-cs04 4.2.2.2 MMIO Device Register Layout
    if size != 4 || offset % 4 != 0 {
        error!(
            "The driver must only use 32 bit wide and aligned reads for \
        reading the control registers on the MMIO transport. See \
        virtio-v1.0-cs04 4.2.2.2 MMIO Device Register Layout."
        );
    }

    // virtio-v1.0-cs04 Table 4.1
    match offset {
        // Magic value
        // 0x74726976 (a Little Endian equivalent of the “virt” string).
        VIRTIO_MMIO_MAGIC_VALUE => VIRT_MAGIC,

        // Device version number
        // 0x2. Note: Legacy devices (see 4.2.4 Legacy interface) used 0x1.
        VIRTIO_MMIO_VERSION => VIRT_MMIO_VERSION,

        // Virtio Subsystem Device ID (see virtio-v1.0-cs04 sec. 5 for values)
        // Value 0x0 is used to define a system memory map with placeholder
        // devices at static, well known addresses.
        VIRTIO_MMIO_DEVICE_ID => dev.vqdev.dev_id as u32,

        // Virtio Subsystem Vendor ID
        VIRTIO_MMIO_VENDOR_ID => VIRT_MMIO_VENDOR,

        // Flags representing features the device supports
        VIRTIO_MMIO_DEVICE_FEATURES => {
            if dev.status & VIRTIO_CONFIG_S_DRIVER == 0 {
                error!(
                    "Attempt to read device features before setting the \
                DRIVER status bit. See virtio-v1.0-cs04 s3.1.1 Device Initialization"
                );
            }
            (if dev.dev_feat_sel > 0 {
                dev.vqdev.dev_feat >> 32 // high 32 bits requested
            } else {
                dev.vqdev.dev_feat & 0xffffffff // low 32 bits requested
            }) as u32
        }

        // Maximum virtual queue size
        // Returns the maximum size (number of elements) of the queue the device
        // is ready to process or zero (0x0) if the queue is not available.
        // Applies to the queue selected by writing to QueueSel.
        VIRTIO_MMIO_QUEUE_NUM_MAX => {
            if dev.qsel as usize >= dev.vqdev.vqs.len() {
                0
            } else {
                dev.vqdev.vqs[dev.qsel as usize].qnum_max
            }
        }

        // Virtual queue ready bit
        // Applies to the queue selected by writing to QueueSel.
        VIRTIO_MMIO_QUEUE_READY => {
            if dev.qsel as usize >= dev.vqdev.vqs.len() {
                0
            } else {
                dev.vqdev.vqs[dev.qsel as usize].qready
            }
        }

        // Interrupt status
        // Bit mask of events that caused the device interrupt to be asserted.
        // bit 0: Used Ring Update
        // bit 1: Configuration Change
        VIRTIO_MMIO_INTERRUPT_STATUS => dev.status as u32,

        // Device status
        VIRTIO_MMIO_STATUS => dev.status as u32,

        // Configuration atomicity value
        // Contains a version for the device-specific configuration space
        // The driver checks this version before and after accessing the config
        // space, and if the values don't match it repeats the access.
        VIRTIO_MMIO_CONFIG_GENERATION => dev.cfg_gen,
        _ => {
            warn!(
                "attemp to read write-only or invalid device register offset {:x}",
                offset
            );
            0
        }
    }
}

fn virtio_mmio_write(dev: &mut VirtioMmioDev, gpa: usize, _size: u8, value: u32) {
    let offset = gpa - dev.addr as usize;

    if dev.vqdev.dev_id == VirtioId::Reserved {
        error!("attempt to write to a reserved device");
    }

    if offset != VIRTIO_MMIO_STATUS && dev.status & VIRTIO_CONFIG_S_FAILED > 0 {
        warn!("The FAILED status bit is set.");
    }

    match offset {
        VIRTIO_MMIO_DEVICE_FEATURES_SEL => dev.dev_feat_sel = value,
        VIRTIO_MMIO_DRIVER_FEATURES => {
            if dev.status & VIRTIO_CONFIG_S_FEATURES_OK > 0 {
                error!(
                    "The driver is not allowed to activate new features after \
                setting FEATURES_OK"
                );
            } else if dev.dri_feat_sel > 0 {
                dev.vqdev.dri_feat &= 0xffffffff;
                dev.vqdev.dri_feat |= (value as u64) << 32;
            } else {
                dev.vqdev.dri_feat &= 0xffffffffu64 << 32;
                dev.vqdev.dri_feat |= value as u64;
            }
            error!("driver features: {:x}", dev.vqdev.dri_feat);
        }
        VIRTIO_MMIO_DRIVER_FEATURES_SEL => dev.dri_feat_sel = value,
        VIRTIO_MMIO_QUEUE_SEL => dev.qsel = value,
        VIRTIO_MMIO_QUEUE_NUM => {
            let qsel = dev.qsel as usize;
            if qsel < dev.vqdev.vqs.len() {
                let vq = &mut dev.vqdev.vqs[qsel];
                if value <= vq.qnum_max {
                    vq.virtq.num = value;
                } else {
                    error!(
                        "write a value to QueueNum which is greater than \
                    QueueNumMax"
                    );
                }
            } else {
                error!("qsel has an invalid value. qsel >= vqs.len()");
            }
        }
        VIRTIO_MMIO_QUEUE_READY => {
            let qsel = dev.qsel as usize;
            if qsel < dev.vqdev.vqs.len() {
                let vq = &mut dev.vqdev.vqs[qsel];
                if vq.qready == 0x0 && value == 0x1 {
                    vq.virtq_sender.send(vq.virtq.clone()).unwrap();
                } else if vq.qready == 0x1 && value == 0x0 {
                    // send a index None to indicate that this virtq is not
                    // available any more
                    vq.index_sender.send(None).unwrap();
                }
                vq.qready = value;
            } else {
                error!("qsel has an invalid value. qsel >= vqs.len()");
            }
        }
        VIRTIO_MMIO_QUEUE_NOTIFY => {
            let q_index = value as usize;
            if dev.status & VIRTIO_CONFIG_S_DRIVER_OK == 0 {
                error!("{} notify device before DRIVER_OK is set", dev.vqdev.name);
            } else if q_index < dev.vqdev.vqs.len() {
                let vq = &dev.vqdev.vqs[q_index];
                let virtq = &vq.virtq;
                let index: u16 = read_host_mem(virtq.avail as u64, 1);
                vq.index_sender.send(Some(index)).unwrap();

                // error!("index {} is send to vq {}", index, q_index);
                // let used_flags: u16 = read_host_mem(virtq.used as u64, 0);
                // write_host_mem(virtq.used as u64, 0, used_flags | VRING_USED_F_NO_NOTIFY);
                // if value == 0 {
                //     let recv_q = &dev.vqdev.vqs[0].read().unwrap().vring;
                //     let used_flags: u16 = read_host_mem(recv_q.used as u64, 0);
                //     error!("used_flag = {}", used_flags);
                //     write_host_mem(recv_q.used as u64, 0, used_flags | VRING_USED_F_NO_NOTIFY);
                //     let flags: u16 = read_host_mem(recv_q.avail as u64, 0);
                //     let index: u16 = read_host_mem(recv_q.avail as u64, 1);
                //     let ring0: u16 = read_host_mem(
                //         recv_q.avail as u64,
                //         2 + ((index as u32 + recv_q.num - 1) % recv_q.num) as u64,
                //     );
                //     error!(
                //         "recv_q, desc ={:x}, avai={:x}, used={:x}",
                //         recv_q.desc, recv_q.avail, recv_q.used
                //     );
                //     error!("flags = {:x}, index={}, ring0={}", flags, index, ring0);
                //     error!("ok vq 0 has some data");
                // } else {
                //     unimplemented!()
                // }
                // let the corresponding thread to process data
            }
        }
        VIRTIO_MMIO_INTERRUPT_ACK => {
            if value & !0x3 > 0 {
                error!(
                    "{} set undefined bits in InterruptAck register",
                    dev.vqdev.name
                );
            }
            *dev.isr.write().unwrap() &= !value;
        }
        VIRTIO_MMIO_STATUS => {
            let mut value = value as u8;
            error!("virtio: write {:b} to status", value);
            if value == 0 {
                device_reset(dev);
            } else if dev.status & !value != 0 {
                error!("The driver must not clear any device status bits, except as a result of resetting the device.")
            } else if dev.status & VIRTIO_CONFIG_S_FAILED != 0 && dev.status != value {
                error!("The driver must reset the device after setting the FAILED status bit, before attempting to re-initialize the device.");
            } else {
                if value & VIRTIO_CONFIG_S_ACKNOWLEDGE > 0 {
                    if value & VIRTIO_CONFIG_S_DRIVER > 0 {
                        if value & VIRTIO_CONFIG_S_FEATURES_OK > 0 {
                            if dev.status & VIRTIO_CONFIG_S_FEATURES_OK > 0 {
                                if value & VIRTIO_CONFIG_S_DRIVER_OK > 0 {
                                    error!("the device is alive");
                                } else {
                                    error!("feature is verified but driver is not ok");
                                }
                            } else {
                                if let Err(s) = dev.vqdev.verify_feat() {
                                    error!("{}", s);
                                    value &= !VIRTIO_CONFIG_S_FEATURES_OK;
                                } else {
                                    // value &= !VIRTIO_CONFIG_S_FEATURES_OK;
                                    error!("feature verified");
                                }
                                if value & VIRTIO_CONFIG_S_DRIVER_OK != 0 {
                                    error!("the driver cannot set feature_ok and driver_ok at the same time");
                                    value &= !VIRTIO_CONFIG_S_DRIVER_OK;
                                } else {
                                    error!("the driver will re-verify feature-ok")
                                }
                            }
                        } else {
                            error!("the driver will read feature");
                        }
                    } else {
                        error!(
                            "the driver does not know how to drive {} for now",
                            dev.vqdev.name
                        );
                    }
                } else {
                    error!("The driver has not noticed the device, {}", dev.vqdev.name);
                }
            }
            dev.status = value;
            error!("dev.status = {:b}", value);
        }
        VIRTIO_MMIO_QUEUE_DESC_LOW => {
            let qsel = dev.qsel as usize;
            if qsel < dev.vqdev.vqs.len() {
                let vq = &mut dev.vqdev.vqs[qsel];
                if vq.qready != 0 {
                    error!(
                        "Attempt to access QueueDescLow on queue {}, which has nonzero QueueReady.",
                        qsel
                    );
                } else {
                    set_addr_low(&mut vq.virtq.desc, value, 16);
                }
            } else {
                error!("write to desc_low of invalid vq, qsel = {}", qsel);
            }
        }
        VIRTIO_MMIO_QUEUE_DESC_HIGH => {
            let qsel = dev.qsel as usize;
            if qsel < dev.vqdev.vqs.len() {
                let vq = &mut dev.vqdev.vqs[qsel];
                if vq.qready != 0 {
                    error!(
                        "Attempt to access QueueDescHigh on queue {}, which has nonzero QueueReady.",
                        qsel
                    );
                } else {
                    set_addr_high(&mut vq.virtq.desc, value);
                }
            } else {
                error!("write to desc_high invalid vq, qsel = {}", qsel);
            }
        }
        VIRTIO_MMIO_QUEUE_AVAIL_LOW => {
            let qsel = dev.qsel as usize;
            if qsel < dev.vqdev.vqs.len() {
                let vq = &mut dev.vqdev.vqs[qsel];
                if vq.qready != 0 {
                    error!(
                        "Attempt to access VIRTIO_MMIO_QUEUE_AVAIL_LOW on queue {}, which has nonzero QueueReady.",
                        qsel
                    );
                } else {
                    set_addr_low(&mut vq.virtq.avail, value, 2);
                }
            } else {
                error!("write to invalid vq, qsel = {}", qsel);
            }
        }
        VIRTIO_MMIO_QUEUE_AVAIL_HIGH => {
            let qsel = dev.qsel as usize;
            let vq = &mut dev.vqdev.vqs[qsel];
            set_addr_high(&mut vq.virtq.avail, value);
        }
        VIRTIO_MMIO_QUEUE_USED_LOW => {
            let qsel = dev.qsel as usize;
            let vq = &mut dev.vqdev.vqs[qsel];
            set_addr_low(&mut vq.virtq.used, value, 4);
        }
        VIRTIO_MMIO_QUEUE_USED_HIGH => {
            //4.2.2.2 Driver Requirements: MMIO Device Register Layout
            let qsel = dev.qsel as usize;
            let vq = &mut dev.vqdev.vqs[qsel];
            set_addr_high(&mut vq.virtq.used, value);
        }
        _ => unimplemented!(),
    }
}

fn set_addr_low(addr: &mut usize, value: u32, align: u32) {
    if value % align != 0 {
        error!("address {:x} not aligned", value);
    } else {
        *addr &= !0xffffffff;
        *addr |= value as usize;
    }
}

fn set_addr_high(addr: &mut usize, value: u32) {
    *addr &= 0xffffffff;
    *addr |= (value as usize) << 32;
}

pub fn virtio_mmio(
    _vcpu: &VCPU,
    gth: &mut GuestThread,
    gpa: usize,
    reg_val: &mut u64,
    size: u8,
    store: bool,
) -> Result<(), Error> {
    let mask = match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffffffff,
        _ => unreachable!(),
    };
    if store {
        // let devs = gth.vm.virtio_mmio_dev
        let mut dev = gth.vm.virtio_mmio_dev[0].lock().unwrap();
        error!(
            "store 0x{:x} to gpa = 0x{:x}, size = {}",
            *reg_val & mask,
            gpa,
            size
        );
        virtio_mmio_write(&mut *dev, gpa, size, *reg_val as u32)
    } else {
        let dev = &gth.vm.virtio_mmio_dev[0].lock().unwrap();
        let val = virtio_mmio_read(dev, gpa, size);
        error!(
            "read from gpa = 0x{:x}, size = {}, return {:x}",
            gpa, size, val
        );
        *reg_val = val as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    use std::io::Read;
    use std::mem::size_of;
    use std::sync::mpsc::channel;

    #[test]
    fn peek_input() {
        let mut tri = [];
        let re = std::io::stdin().read(&mut tri);
        if re.is_ok() {
            println!("some data is ready, r={:?}", &re);
        } else {
            println!("peek error");
        }
        let mut input_str = String::new();
        std::io::stdin().read_line(&mut input_str).unwrap();
        println!("get string: {}", input_str);
    }
    #[test]
    fn virto_struct_test() {
        assert_eq!(size_of::<VirtqDesc>(), 16);
        let (tx, rx) = channel();

        // This send is always successful
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        tx.send(3).unwrap();

        // This send will fail because the receiver is gone
        // drop(rx);
        // assert_eq!(tx.send(1).unwrap_err().0, 1);
        println!("{:?}", rx.recv());
        println!("{:?}", rx.recv());
        println!("{:?}", rx.recv());
        println!("{:?}", rx.recv());
    }
}
