/* This marks a buffer as continuing via the next field. */
pub const VIRTQ_DESC_F_NEXT: u64 = 1;
/* This marks a buffer as write-only (otherwise read-only). */
pub const VIRTQ_DESC_F_WRITE: u64 = 2;
/* This means the buffer contains a list of buffer descriptors. */
pub const VIRTQ_DESC_F_INDIRECT: u64 = 4;

/* The device uses this in used->flags to advise the driver: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization. */
pub const VIRTQ_USED_F_NO_NOTIFY: u64 = 1;
/* The driver uses this in avail->flags to advise the device: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.  */
pub const VIRTQ_AVAIL_F_NO_INTERRUPT: u64 = 1;

/* Support for indirect descriptors */
pub const VIRTIO_F_INDIRECT_DESC: u64 = 28;

/* Support for avail_event and used_event fields */
pub const VIRTIO_F_EVENT_IDX: u64 = 29;

/* Arbitrary descriptor layouts. */
pub const VIRTIO_F_ANY_LAYOUT: u64 = 27;

pub const VIRTQ_SIZE_MAX: u16 = 1 << 15;

use std::mem::size_of;

// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/listings/virtio_queue.h

#[repr(C, packed)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C, packed)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[derive(Debug, Clone)]
pub struct Virtq {
    pub num: u32,
    pub desc: usize,
    pub avail: usize,
    pub used: usize,
}

impl Virtq {
    pub fn new(num: u32) -> Self {
        Virtq {
            num,
            desc: 0,
            avail: 0,
            used: 0,
        }
    }

    pub fn read_desc(&self, index: u16) -> VirtqDesc {
        let real_index = index as usize % self.num as usize;
        let ptr = (self.desc + size_of::<VirtqDesc>() * real_index) as *const VirtqDesc;
        unsafe { ptr.read() }
    }

    pub fn push_used(&self, id: u16, len: u32) {
        let used_index = self.used_index();
        let real_used_index = used_index as usize % self.num as usize;
        let used_elem = VirtqUsedElem { id: id as u32, len };
        let ptr_elem =
            (self.used + 4 + size_of::<VirtqUsedElem>() * real_used_index) as *mut VirtqUsedElem;
        unsafe {
            ptr_elem.write(used_elem);
        }
        self.set_used_index(used_index.wrapping_add(1));
    }

    pub fn used_flags(&self) -> u16 {
        let ptr = self.used as *const u16;
        unsafe { ptr.read() }
    }

    pub fn used_index(&self) -> u16 {
        let ptr = (self.used + 2) as *const u16;
        unsafe { ptr.read() }
    }

    fn set_used_index(&self, index: u16) {
        let ptr = (self.used + 2) as *mut u16;
        unsafe { ptr.write(index) }
    }

    pub fn set_used_flags(&self, flags: u16) {
        let ptr = self.used as *mut u16;
        unsafe { ptr.write(flags) }
    }

    pub fn read_avail(&self, index: u16) -> u16 {
        let real_index = index as usize % self.num as usize;
        let ptr = (self.avail + 4 + size_of::<u16>() * real_index) as *const u16;
        unsafe { ptr.read() }
    }

    pub fn avail_flags(&self) -> u16 {
        let ptr = self.avail as *const u16;
        unsafe { ptr.read() }
    }

    pub fn avail_index(&self) -> u16 {
        let ptr = (self.avail + 2) as *const u16;
        unsafe { ptr.read() }
    }
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_size() {
        println!("sizeof virtusedeleent = {}", size_of::<VirtqUsedElem>());
        println!("{}", size_of::<Option<u16>>());
        println!("{}", size_of::<u32>());
    }
}
