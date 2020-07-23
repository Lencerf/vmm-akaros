use super::*;
use crate::vmexit::print_cstr_file;
use std::io::Read;

fn find_avail_bufs<F>(virtq: &Virtq, index: u16, mut handler: F) -> u16
where
    F: FnMut(&VirtqDesc) -> bool,
{
    let desc_head = virtq.read_avail(index);
    let mut desc_index = desc_head;
    loop {
        let desc = virtq.read_desc(desc_index);
        let should_continue = handler(&desc);
        if should_continue && desc.flags & VRING_DESC_F_NEXT > 0 {
            desc_index = desc.next;
        } else {
            break;
        }
    }
    desc_head
}

fn cons_recv_fn(
    irq: u32,
    recv_index: AvailIndexReceiver,
    recv_virtq: Receiver<Virtq>,
    irq_sender: Sender<u32>,
    isr: Arc<RwLock<u32>>,
) {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
        continue;
        let virtq_result = recv_virtq.recv();
        if virtq_result.is_err() {
            break;
        }
        let virtq = virtq_result.unwrap();
        warn!("get virtq: {:x?}", &virtq);
        let mut current_index = 0;
        loop {
            let index_result = recv_index.recv();
            if index_result.is_err() {
                break;
            }
            let maybe_index = index_result.unwrap();
            if maybe_index.is_none() {
                break;
            }
            let avail_index = maybe_index.unwrap();
            while current_index < avail_index {
                let mut bufs = Vec::new();
                let desc_head = find_avail_bufs(&virtq, current_index, |desc| {
                    let flags = desc.flags;
                    if flags & VRING_DESC_F_WRITE != 0 {
                        let buf = unsafe {
                            std::slice::from_raw_parts_mut(desc.addr as *mut u8, desc.len as usize)
                        };
                        let io_slice = std::io::IoSliceMut::new(buf);
                        bufs.push(io_slice);
                        true
                    } else {
                        false
                    }
                });
                if let Ok(size) = stdin().read_vectored(&mut bufs) {
                    virtq.push_used(desc_head, size as u32);
                    // println!(
                    //     "read {} bytes, index updated to {}",
                    //     size,
                    //     virtq.used_index()
                    // );
                }
                current_index += 1;
            }
            *isr.write().unwrap() |= VIRTIO_MMIO_INT_VRING;
            let avail_flag = virtq.avail_flags();
            if avail_flag & VRING_AVAIL_F_NO_INTERRUPT == 0 {
                irq_sender.send(irq).unwrap();
                // println!("send irq {}", irq);
            }
        }
    }
}

fn cons_trans_fn(
    irq: u32,
    recv_index: AvailIndexReceiver,
    recv_virtq: Receiver<Virtq>,
    irq_sender: Sender<u32>,
    isr: Arc<RwLock<u32>>,
) {
    loop {
        let virtq_result = recv_virtq.recv();
        if virtq_result.is_err() {
            break;
        }
        let virtq = virtq_result.unwrap();
        warn!("get virtq: {:x?}", &virtq);
        let mut current_index = 0;
        loop {
            let index_result = recv_index.recv();
            if index_result.is_err() {
                break;
            }
            let maybe_index = index_result.unwrap();
            if maybe_index.is_none() {
                break;
            }
            let avail_index = maybe_index.unwrap();
            while current_index < avail_index {
                // let desc_head = virtq.read_avail(current_index);
                // let mut desc_index = desc_head;
                // loop {
                //     let desc = virtq.read_desc(desc_index);
                //     let flag = desc.flags;
                //     if flag & VRING_DESC_F_WRITE == 0 {
                //         unsafe {
                //             print_cstr(desc.addr as *const u8, desc.len as u64);
                //         }
                //     }
                //     if desc.flags & VRING_DESC_F_NEXT > 0 {
                //         desc_index = desc.next;
                //     } else {
                //         break;
                //     }
                // }
                let desc_head = find_avail_bufs(&virtq, current_index, |desc| {
                    let flags = desc.flags;
                    if flags & VRING_DESC_F_WRITE == 0 {
                        unsafe {
                            // print_cstr(desc.addr as *const u8, desc.len as u64);
                            print_cstr_file(
                                desc.addr as *const u8,
                                desc.len as u64,
                                "/Users/changyuanl/test/printc_output/hvc0_output.txt\0".as_ptr(),
                            )
                        }
                        true
                    } else {
                        false
                    }
                });
                virtq.push_used(desc_head, 0);
                current_index += 1;
            }
            // *isr.write().unwrap() |= VIRTIO_MMIO_INT_VRING;
            // let avail_flag = virtq.avail_flags();
            // if avail_flag & VRING_AVAIL_F_NO_INTERRUPT == 0 {
            //     irq_sender.send(irq).unwrap();
            // }
        }
    }
}

impl VirtioVqDev {
    pub fn new_console(
        name: String,
        irq: u32,
        irq_sender: Sender<u32>,
        isr: Arc<RwLock<u32>>,
    ) -> Self {
        let receive = VirtioVq::new(
            format!("{}_recv", name),
            64,
            cons_recv_fn,
            irq,
            irq_sender.clone(),
            isr.clone(),
        );
        let transmit = VirtioVq::new(
            format!("{}_trans", name),
            64,
            cons_trans_fn,
            irq,
            irq_sender.clone(),
            isr.clone(),
        );
        let vqs = vec![receive, transmit];
        VirtioVqDev {
            name,
            dev_id: VirtioId::Console,
            dev_feat: 1 << VIRTIO_F_VERSION_1, //  | 1 << VIRTIO_RING_F_INDIRECT_DESC
            dri_feat: 0,
            cfg: vec![0u32; 3], // 5.3.4
            cfg_d: vec![0u32; 3],
            vqs,
        }
    }
}

impl VirtioMmioDev {
    pub fn new_console(addr: usize, irq: u32, name: String, irq_sender: Sender<u32>) -> Self {
        let isr = Arc::new(RwLock::new(0));
        let console = VirtioVqDev::new_console(name, irq, irq_sender, isr.clone());
        VirtioMmioDev {
            addr,
            dev_feat_sel: 0,
            dri_feat_sel: 0,
            qsel: 0,
            isr,
            status: 0,
            cfg_gen: 0,
            vqdev: console,
            irq,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn print_cstr_test() {
        let a = "啊";
        let ptr = a.as_ptr();
        unsafe {
            print_cstr(ptr, a.len() as u64);
        }
        let b = a.as_bytes();
        for byte in b.iter() {
            println!("{}", *byte as char);
        }
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).unwrap();
        println!("len = {}", buf.len())
    }
}
