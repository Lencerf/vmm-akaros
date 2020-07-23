/* SPDX-License-Identifier: GPL-2.0-only */

fn main() {
    println!("cargo:rustc-link-lib=framework=Hypervisor");

    cc::Build::new().file("c_src/cpuid.c").compile("cpuid");
    cc::Build::new().file("c_src/hlt.s").compile("hlt");
    cc::Build::new().file("c_src/vmcall.c").compile("vmcall");
    cc::Build::new().file("c_src/sysctl.c").compile("sysctl");
    cc::Build::new()
        .file("c_src/serial_c.c")
        .compile("serial_c");
}
