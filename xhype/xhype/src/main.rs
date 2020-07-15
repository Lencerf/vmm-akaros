/* SPDX-License-Identifier: GPL-2.0-only */
use std::env;
use std::sync::{Arc, RwLock};
use xhype::err::Error;
use xhype::{linux, VMManager};

fn kernel_test() {
    let memsize = 1 << 30; // 1GB
    let vmm = VMManager::new().unwrap();
    let kn_path = env::var("KN_PATH").unwrap();
    let rd_path = env::var("RD_PATH").ok();
    let cmd_line = env::var("CMD_Line").unwrap_or("auto".to_string());
    let vm = Arc::new(RwLock::new(vmm.create_vm(1).unwrap()));
    let guest_threads = linux::load_linux64(&vm, kn_path, rd_path, cmd_line, memsize).unwrap();
    let join_handlers: Vec<std::thread::JoinHandle<Result<(), Error>>> =
        guest_threads.into_iter().map(|gth| gth.start()).collect();
    for (i, handler) in join_handlers.into_iter().enumerate() {
        let r = handler.join().unwrap();
        match r {
            Ok(_) => {
                println!("guest thread {} terminates correctly", i);
            }
            Err(e) => {
                println!("guest thread {} terminates with error: {:?}", i, e);
            }
        }
    }
}

fn main() {
    env_logger::init();
    kernel_test();
}
