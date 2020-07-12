/* SPDX-License-Identifier: GPL-2.0-only */
#[inline]
pub fn round_up(num: usize) -> usize {
    (num + 0xfff) & !0xfff
}

#[inline]
pub fn round_down(num: usize) -> usize {
    num & !0xfff
}

extern "C" {
    pub fn get_bus_frequency_c() -> u64;
    pub fn get_tsc_frequency_c() -> u64;
}

pub fn get_bus_frequency() -> u64 {
    unsafe { get_bus_frequency_c() }
}

pub fn get_tsc_frequency() -> u64 {
    unsafe { get_tsc_frequency_c() }
}

extern "C" {
    fn mach_absolute_time() -> u64;
}

pub fn mach_abs_time_ns() -> u64 {
    // fix me, call mach_timebase_info
    unsafe { mach_absolute_time() }
}
