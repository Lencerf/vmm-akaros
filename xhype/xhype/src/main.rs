#![cfg_attr(feature = "vthread_closure", feature(fn_traits))]
use std::env;
use std::sync::{Arc, RwLock};
use xhype::vthread::Builder;
use xhype::{loader, VMManager};

static mut NUM_A: i32 = 4;
static mut NUM_B: i32 = 2;

fn change_a() {
    unsafe {
        NUM_A = 2;
    }
}

fn change_b() {
    unsafe {
        NUM_B = 100;
    }
}

fn vthread_test() {
    println!("initially, a = {}, b = {}", unsafe { NUM_A }, unsafe {
        NUM_B
    });
    let vmm = VMManager::new().unwrap();
    let vm = Arc::new(RwLock::new(vmm.create_vm(1).unwrap()));
    let vth_a = if cfg!(feature = "vthread_closure") {
        Builder::new(&vm)
            .spawn(|| unsafe {
                NUM_A = 3;
            })
            .unwrap()
    } else {
        Builder::new(&vm).spawn(change_a).unwrap()
    };
    let vth_b = if cfg!(feature = "vthread_closure") {
        Builder::new(&vm)
            .spawn(|| unsafe {
                NUM_B = 101;
            })
            .unwrap()
    } else {
        Builder::new(&vm)
            .name("vth_b".to_string())
            .spawn(change_b)
            .unwrap()
    };
    vth_a.join().unwrap();
    vth_b.join().unwrap();
    println!("a = {}, b = {}", unsafe { NUM_A }, unsafe { NUM_B });
}

fn kernel_test() {
    let memsize = 1 << 30;
    let vmm = VMManager::new().unwrap();
    let kn_path = env::var("KN_PATH").unwrap();
    let rd_path = env::var("RD_PATH").ok();
    let cmd_line = env::var("CMD_Line").unwrap_or("auto".to_string());
    let vm = Arc::new(RwLock::new(vmm.create_vm(1).unwrap()));
    let gths = loader::load_linux64(&vm, kn_path, rd_path, cmd_line, memsize).unwrap();
    let vcpu = vmm.create_vcpu().unwrap();
    match gths[0].run_on(&vcpu) {
        Ok(_) => {
            println!("guest terminates normally");
        }
        Err(e) => {
            println!("guest terminates with error: {:?}", e);
        }
    }
}

fn main() {
    env_logger::init();
    vthread_test();
    kernel_test();
}