use std::ffi::c_void;
/// Hypervisor Framework return code
pub type hv_return_t = u32;

extern "C" {
	/// Enumerate supported hypervisor capabilities
	pub fn hv_capability(capability: super::HVCap, value: *mut u64) -> hv_return_t;
}

/// Options for hv_vcpu_create()
pub type hv_vm_options_t = u64;

// Creating and Destroying VM Instances
extern "C" {
	/// Creates a VM instance for the current Mach task
	pub fn hv_vm_create(flags: hv_vm_options_t) -> hv_return_t;

	/// Destroys the VM instance associated with the current Mach task
	pub fn hv_vm_destroy() -> hv_return_t;
}

/// Type of a guest address space
pub type hv_vm_space_t = u32;

extern "C" {
	/// Creates an additional guest address space for the current task
	pub fn hv_vm_space_create(asid: *mut hv_vm_space_t) -> hv_return_t;
	/// Destroys the address space instance associated with the current task
	pub fn hv_vm_space_destroy(asid: hv_vm_space_t) -> hv_return_t;
}

/// Type of a user virtual address
pub type hv_uvaddr_t = usize;

/// Guest physical memory region permissions for hv_vm_map()
/// and hv_vm_protect()
pub type hv_memory_flags_t = u64;

/// Type of a guest physical address
pub type hv_gpaddr_t = usize;

// Managing Memory Regions
extern "C" {
	/// Maps a region in the virtual address space of the current
	/// task into the guest physical address space of the VM
	pub fn hv_vm_map(
		uva: hv_uvaddr_t,
		gpa: hv_gpaddr_t,
		size: usize,
		flags: hv_memory_flags_t,
	) -> hv_return_t;

	/// Unmaps a region in the guest physical address space of the VM
	pub fn hv_vm_unmap(gpa: hv_gpaddr_t, size: usize) -> hv_return_t;

	// /// Modifies the permissions of a region in the guest physical
	// /// address space of the VM
	// pub fn hv_vm_protect(gpa: hv_gpaddr_t, size: usize, flags: hv_memory_flags_t) -> hv_return_t;

	/// Maps a region in the virtual address space of the current task
	/// into a guest physical address space of the VM
	pub fn hv_vm_map_space(
		asid: hv_vm_space_t,
		uva: hv_uvaddr_t,
		gpa: hv_gpaddr_t,
		size: usize,
		flags: hv_memory_flags_t,
	) -> hv_return_t;

	/// Unmaps a region in a guest physical address space of the VM
	pub fn hv_vm_unmap_space(asid: hv_vm_space_t, gpa: hv_gpaddr_t, size: usize) -> hv_return_t;

// /// Modifies the permissions of a region in a guest physical address space of the VM
// pub fn hv_vm_protect_space(
// 	asid: hv_vm_space_t,
// 	gpa: hv_gpaddr_t,
// 	size: usize,
// 	flags: hv_memory_flags_t,
// ) -> hv_return_t;
}

/// Type of a vCPU ID
pub type hv_vcpuid_t = u32;

// Creating and Managing vCPU Instances
extern "C" {
	/// Creates a vCPU instance for the current thread
	pub fn hv_vcpu_create(vcpu: *mut hv_vcpuid_t, flags: hv_vm_options_t) -> hv_return_t;

	/// Executes a vCPU
	pub fn hv_vcpu_run(vcpu: hv_vcpuid_t) -> hv_return_t;

	// /// Forces an immediate VMEXIT of a set of vCPUs of the VM
	// pub fn hv_vcpu_interrupt(vcpu: *const hv_vcpuid_t, vcpu_count: u32) -> hv_return_t;

	// /// Returns the cumulative execution time of a vCPU in nanoseconds
	// pub fn hv_vcpu_get_exec_time(vcpu: hv_vcpuid_t, time: *mut u64) -> hv_return_t;

	// /// Forces flushing of cached vCPU state
	// pub fn hv_vcpu_flush(vcpu: hv_vcpuid_t) -> hv_return_t;

	// /// Invalidates the TLB of a vCPU
	// pub fn hv_vcpu_invalidate_tlb(vcpu: hv_vcpuid_t) -> hv_return_t;

	/// Destroys the vCPU instance associated with the current thread
	pub fn hv_vcpu_destroy(vcpu: hv_vcpuid_t) -> hv_return_t;

	/// Associates the vCPU instance with an allocated address space
	pub fn hv_vcpu_set_space(vcpu: hv_vcpuid_t, asid: hv_vm_space_t) -> hv_return_t;
}

// Accessing Registers
extern "C" {
	/// Returns the current value of an architectural x86 register
	/// of a vCPU
	pub fn hv_vcpu_read_register(
		vcpu: hv_vcpuid_t,
		reg: super::X86Reg,
		value: *mut u64,
	) -> hv_return_t;

	/// Sets the value of an architectural x86 register of a vCPU
	pub fn hv_vcpu_write_register(vcpu: hv_vcpuid_t, reg: super::X86Reg, value: u64)
		-> hv_return_t;
}

// Accessing Floating Point (FP) State
extern "C" {
	/// Returns the current architectural x86 floating point and
	/// SIMD state of a vCPU
	pub fn hv_vcpu_read_fpstate(vcpu: hv_vcpuid_t, buffer: *mut c_void, size: usize)
		-> hv_return_t;

	/// Sets the architectural x86 floating point and SIMD state of
	/// a vCPU
	pub fn hv_vcpu_write_fpstate(
		vcpu: hv_vcpuid_t,
		buffer: *const c_void,
		size: usize,
	) -> hv_return_t;
}

// Accessing Machine Specific Registers (MSRs)
extern "C" {
	/// Enables an MSR to be used natively by the VM
	pub fn hv_vcpu_enable_native_msr(vcpu: hv_vcpuid_t, msr: u32, enable: bool) -> hv_return_t;

	/// Returns the current value of an MSR of a vCPU
	pub fn hv_vcpu_read_msr(vcpu: hv_vcpuid_t, msr: u32, value: *mut u64) -> hv_return_t;

	/// Set the value of an MSR of a vCPU
	pub fn hv_vcpu_write_msr(vcpu: hv_vcpuid_t, msr: u32, value: u64) -> hv_return_t;
}

// Managing Timestamp-Counters (TSC)
extern "C" {
	/// Synchronizes guest Timestamp-Counters (TSC) across all vCPUs
	pub fn hv_vm_sync_tsc(tsc: u64) -> hv_return_t;
}

// Managing Virtual Machine Control Structure (VMCS)
extern "C" {
	/// Returns the current value of a VMCS field of a vCPU
	pub fn hv_vmx_vcpu_read_vmcs(vcpu: hv_vcpuid_t, field: u32, value: *mut u64) -> hv_return_t;

	/// Sets the value of a VMCS field of a vCPU
	pub fn hv_vmx_vcpu_write_vmcs(vcpu: hv_vcpuid_t, field: u32, value: u64) -> hv_return_t;

	/// Returns the VMX capabilities of the host processor
	pub fn hv_vmx_read_capability(field: super::VMXCap, value: *mut u64) -> hv_return_t;

	/// Sets the address of the guest APIC for a vCPU in the
	/// guest physical address space of the VM
	pub fn hv_vmx_vcpu_set_apic_address(vcpu: hv_vcpuid_t, gpa: hv_gpaddr_t) -> hv_return_t;
}
