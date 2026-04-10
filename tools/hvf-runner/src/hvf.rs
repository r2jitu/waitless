// tools/hvf-runner/src/hvf.rs
//
// FFI bindings and thin safe wrappers for Apple Hypervisor.framework.
// Scoped to what the Phase 0 smoke tests need:
//   - hv_vm_create / hv_vm_destroy / hv_vm_map
//   - hv_vcpu_create / hv_vcpu_run / hv_vcpu_destroy
//   - hv_vcpu_get_reg / hv_vcpu_set_reg
//   - hv_vcpu_get_sys_reg / hv_vcpu_set_sys_reg
//   - hv_gic_config_create / hv_gic_config_set_*_base / hv_gic_create
//   - hv_gic_set_spi / hv_gic_get_redistributor_base
//
// Phase 1 will extend this with additional sys reg enum values, exit reason
// decoding helpers, and wrapper structs (Vm, Vcpu) that own their handles
// and clean up on drop. For now we keep the shape minimal so the smoke
// test can go directly to the raw calls where that is clearer than a
// safe wrapper.
//
// All function signatures here were transcribed directly from the SDK
// headers at:
//   /Library/Developer/CommandLineTools/SDKs/MacOSX26.4.sdk/
//   System/Library/Frameworks/Hypervisor.framework/Versions/A/Headers/
// If a discrepancy with the SDK is discovered at runtime, treat this
// file as the source of truth to fix.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

use std::ffi::c_void;
use std::fmt;

// ─── Primitive types (from hv_kern_types.h, hv_vm_types.h, hv_vcpu_types.h) ──

pub type hv_return_t = i32; // mach_error_t
pub type hv_ipa_t = u64; //   Guest physical address
pub type hv_memory_flags_t = u64;
pub type hv_vcpu_t = u64;
pub type hv_vm_config_t = *mut c_void; // nullable
pub type hv_vcpu_config_t = *mut c_void; // nullable
pub type hv_gic_config_t = *mut c_void;

// ─── Memory flags (from hv_kern_types.h) ─────────────────────────────────────

pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;

// ─── Return codes (from arm64/hv/hv_kern_types.h) ────────────────────────────
//
// Apple's hv_error.h is x86_64-only; the arm64 values live in
// <arm64/hv/hv_kern_types.h>. The x86_64 header is missing
// HV_ILLEGAL_GUEST_STATE (0xfae94004) and has HV_FAULT instead of
// HV_EXISTS at 0xfae94008. Use the arm64 values on arm64.

pub const HV_SUCCESS: hv_return_t = 0;
pub const HV_ERROR: hv_return_t = 0xfae9_4001u32 as i32;
pub const HV_BUSY: hv_return_t = 0xfae9_4002u32 as i32;
pub const HV_BAD_ARGUMENT: hv_return_t = 0xfae9_4003u32 as i32;
pub const HV_ILLEGAL_GUEST_STATE: hv_return_t = 0xfae9_4004u32 as i32;
pub const HV_NO_RESOURCES: hv_return_t = 0xfae9_4005u32 as i32;
pub const HV_NO_DEVICE: hv_return_t = 0xfae9_4006u32 as i32;
pub const HV_DENIED: hv_return_t = 0xfae9_4007u32 as i32;
pub const HV_EXISTS: hv_return_t = 0xfae9_4008u32 as i32;
pub const HV_UNSUPPORTED: hv_return_t = 0xfae9_400fu32 as i32;

// ─── Registers (from hv_vcpu_types.h, enum hv_reg) ───────────────────────────
// The C header lets the compiler auto-number sequential values; Rust's
// #[repr(u32)] on an enum gives us the same layout but with explicit
// control. Keep these literal to avoid any surprise if Apple ever
// re-orders the C enum in a future SDK.

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum HvReg {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    Pc = 31,
    Fpcr = 32,
    Fpsr = 33,
    Cpsr = 34,
}

impl HvReg {
    /// X0..X30 as a runtime index. Panics for non-GPR registers.
    pub fn gpr(index: u32) -> Self {
        assert!(index <= 30, "gpr index out of range: {index}");
        // SAFETY: values 0..=30 map directly to X0..X30 variants by
        // construction of the enum above.
        unsafe { std::mem::transmute::<u32, HvReg>(index) }
    }
}

// ─── System registers (from hv_vcpu_types.h, enum hv_sys_reg) ────────────────
// Only the ones Phase 0 and Phase 1 need. More will be added later.

#[repr(u16)]
#[derive(Copy, Clone, Debug)]
pub enum HvSysReg {
    MpidrEl1 = 0xc005,
    EsrEl1 = 0xc290,
    FarEl1 = 0xc300,
    ElrEl1 = 0xc201,
    SpsrEl1 = 0xc200,
    SctlrEl1 = 0xc080,
    CpacrEl1 = 0xc082,
    VbarEl1 = 0xc600,
    CntvCtlEl0 = 0xdf19,
    // MMU setup registers — needed so the guest can use Normal cacheable
    // memory (required for LDXR/STXR and friends).
    MairEl1 = 0xc510,
    TcrEl1 = 0xc102,
    Ttbr0El1 = 0xc100,
    Ttbr1El1 = 0xc101,
    // ACTLR_EL1 — Apple-IMPDEF. Per Hypervisor.framework headers, HVF
    // lets us toggle bit 1 (ACTLR_EL1.EnTSO) which selects the Apple
    // TSO memory model (used by Rosetta). Value 0 = ARMv8 weakly
    // ordered, value 2 = TSO.
    ActlrEl1 = 0xc081,
}

// ─── Exit reasons (from hv_vcpu_types.h, enum hv_exit_reason) ────────────────

pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;
pub const HV_EXIT_REASON_UNKNOWN: u32 = 3;

/// Mirrors `hv_vcpu_exit_exception_t` in hv_vcpu_types.h.
///
/// Layout must exactly match the C struct — the framework writes into
/// our memory via the out-pointer from hv_vcpu_create.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct HvVcpuExitException {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

/// Mirrors `hv_vcpu_exit_t` in hv_vcpu_types.h.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct HvVcpuExit {
    pub reason: u32,
    // C enum is uint32_t; the struct is naturally padded to 8 before
    // the exception field because virtual_address etc. are u64.
    _pad: u32,
    pub exception: HvVcpuExitException,
}

// ─── Interrupt type (from hv_vcpu_types.h, enum hv_interrupt_type) ───────────

pub const HV_INTERRUPT_TYPE_IRQ: u32 = 0;
pub const HV_INTERRUPT_TYPE_FIQ: u32 = 1;

// ─── Raw FFI bindings ────────────────────────────────────────────────────────

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    // VM
    pub fn hv_vm_create(config: hv_vm_config_t) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_map(
        addr: *mut c_void,
        ipa: hv_ipa_t,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;
    pub fn hv_vm_unmap(ipa: hv_ipa_t, size: usize) -> hv_return_t;

    // Guest RAM allocator. EMPIRICAL FINDING (M2 macOS 26.4): hv_vm_allocate
    // does NOT unlock the exclusive monitor — exclusives still fault
    // with DFSC=0x35. Same for plain mmap(MAP_ANON). The header text
    // suggesting hv_vm_allocate gives "memory suitable for guest"
    // refers to memory accounting, not cacheability/exclusive support.
    pub fn hv_vm_allocate(
        uvap: *mut *mut c_void,
        size: usize,
        flags: u64, // hv_allocate_flags_t; HV_ALLOCATE_DEFAULT = 0
    ) -> hv_return_t;
    pub fn hv_vm_deallocate(uva: *mut c_void, size: usize) -> hv_return_t;

    // VM configuration object.
    pub fn hv_vm_config_create() -> hv_vm_config_t;
    pub fn hv_vm_config_get_max_ipa_size(out: *mut u32) -> hv_return_t;
    pub fn hv_vm_config_get_default_ipa_size(out: *mut u32) -> hv_return_t;
    pub fn hv_vm_config_set_ipa_size(
        config: hv_vm_config_t,
        ipa_bit_length: u32,
    ) -> hv_return_t;
    pub fn hv_vm_config_get_el2_supported(out: *mut bool) -> hv_return_t;
    pub fn hv_vm_config_set_el2_enabled(
        config: hv_vm_config_t,
        enabled: bool,
    ) -> hv_return_t;
    pub fn hv_vm_config_get_default_ipa_granule(out: *mut u32) -> hv_return_t;
    pub fn hv_vm_config_set_ipa_granule(
        config: hv_vm_config_t,
        granule: u32,
    ) -> hv_return_t;

    // vCPU lifecycle
    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit_out: *mut *mut HvVcpuExit,
        config: hv_vcpu_config_t,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpus_exit(vcpus: *const hv_vcpu_t, count: u32) -> hv_return_t;

    // Register access
    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: HvReg, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: HvReg, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_sys_reg(
        vcpu: hv_vcpu_t,
        reg: HvSysReg,
        value: *mut u64,
    ) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(
        vcpu: hv_vcpu_t,
        reg: HvSysReg,
        value: u64,
    ) -> hv_return_t;

    // Interrupt injection (fallback — we prefer hv_gic_set_spi with native vGIC)
    pub fn hv_vcpu_set_pending_interrupt(
        vcpu: hv_vcpu_t,
        interrupt_type: u32,
        pending: bool,
    ) -> hv_return_t;

    // VTimer mask (required for HV_EXIT_REASON_VTIMER_ACTIVATED handling)
    pub fn hv_vcpu_set_vtimer_mask(vcpu: hv_vcpu_t, masked: bool) -> hv_return_t;
    pub fn hv_vcpu_get_vtimer_mask(vcpu: hv_vcpu_t, masked: *mut bool) -> hv_return_t;

    // GIC (native vGIC, macOS 15+)
    pub fn hv_gic_config_create() -> hv_gic_config_t;
    pub fn hv_gic_config_set_distributor_base(
        config: hv_gic_config_t,
        ipa: hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_config_set_redistributor_base(
        config: hv_gic_config_t,
        ipa: hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_create(config: hv_gic_config_t) -> hv_return_t;
    pub fn hv_gic_set_spi(intid: u32, level: bool) -> hv_return_t;
    pub fn hv_gic_get_redistributor_base(
        vcpu: hv_vcpu_t,
        redistributor_base: *mut hv_ipa_t,
    ) -> hv_return_t;

    // GIC distributor/redistributor register access. The register enum
    // values from hv_gic_types.h are numerically equal to the standard
    // GICv3 MMIO offsets (e.g. GICD_CTLR = 0x000, GICD_ISENABLER0 =
    // 0x100), so we can use plain u32 offsets without transcribing the
    // whole enum. Required for enabling specific SPIs before hv_gic_set_spi
    // actually delivers them.
    pub fn hv_gic_get_distributor_reg(reg: u32, value: *mut u64) -> hv_return_t;
    pub fn hv_gic_set_distributor_reg(reg: u32, value: u64) -> hv_return_t;

    // GIC redistributor register access (per-vCPU).
    pub fn hv_gic_get_redistributor_reg(
        vcpu: hv_vcpu_t,
        reg: u32,
        value: *mut u64,
    ) -> hv_return_t;
    pub fn hv_gic_set_redistributor_reg(
        vcpu: hv_vcpu_t,
        reg: u32,
        value: u64,
    ) -> hv_return_t;
}

// ─── Error handling ──────────────────────────────────────────────────────────

/// A runner-level error wrapping a raw Hypervisor.framework return code.
///
/// Debug/Display both print the code AND a hint about what commonly
/// causes that code. The entitlement-missing hint on HV_DENIED is the
/// most important one because it catches the very common "I forgot
/// codesign" failure mode.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct HvError(pub hv_return_t);

impl HvError {
    pub fn from_raw(code: hv_return_t) -> Result<(), Self> {
        if code == HV_SUCCESS {
            Ok(())
        } else {
            Err(HvError(code))
        }
    }

    pub fn name(&self) -> &'static str {
        match self.0 {
            HV_SUCCESS => "HV_SUCCESS",
            HV_ERROR => "HV_ERROR",
            HV_BUSY => "HV_BUSY",
            HV_BAD_ARGUMENT => "HV_BAD_ARGUMENT",
            HV_ILLEGAL_GUEST_STATE => "HV_ILLEGAL_GUEST_STATE",
            HV_NO_RESOURCES => "HV_NO_RESOURCES",
            HV_NO_DEVICE => "HV_NO_DEVICE",
            HV_DENIED => "HV_DENIED",
            HV_EXISTS => "HV_EXISTS",
            HV_UNSUPPORTED => "HV_UNSUPPORTED",
            _ => "(unknown hv_return_t)",
        }
    }

    /// Produce a human-readable hint for common failure modes.
    pub fn hint(&self) -> Option<&'static str> {
        match self.0 {
            HV_DENIED => Some(
                "Hypervisor.framework returned HV_DENIED. This almost always means \
                 the binary is not codesigned with the com.apple.security.hypervisor \
                 entitlement. Re-sign with:\n    \
                 codesign --force --sign - --entitlements run-hvf.entitlements <binary>",
            ),
            HV_NO_DEVICE => Some(
                "Hypervisor.framework returned HV_NO_DEVICE. This usually means \
                 hv_vm_create could not acquire the hypervisor device — \
                 check that no other VMM is running and that the entitlement \
                 is in place.",
            ),
            HV_UNSUPPORTED => Some(
                "Hypervisor.framework returned HV_UNSUPPORTED. If this came from \
                 hv_gic_create, it means the host macOS version is older than 15.0 \
                 (native vGIC requires macOS Sonoma or later).",
            ),
            HV_ILLEGAL_GUEST_STATE => Some(
                "Hypervisor.framework returned HV_ILLEGAL_GUEST_STATE. The vCPU \
                 was asked to run with an invalid register configuration — most \
                 commonly PC/PSTATE/SCTLR not consistent with EL1.",
            ),
            _ => None,
        }
    }
}

impl fmt::Debug for HvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HvError({} = 0x{:08x})", self.name(), self.0 as u32)
    }
}

impl fmt::Display for HvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:08x})", self.name(), self.0 as u32)?;
        if let Some(hint) = self.hint() {
            write!(f, "\n  hint: {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for HvError {}

/// Wrap a raw hv_return_t in a Result for ergonomic `?` propagation.
#[inline]
pub fn check(code: hv_return_t) -> Result<(), HvError> {
    HvError::from_raw(code)
}

// ─── ESR_EL1 helpers ─────────────────────────────────────────────────────────
// These are architectural, not HVF-specific, but they live here to keep
// all the "inspect guest exit state" logic in one file for now.

pub const ESR_EC_SHIFT: u64 = 26;
pub const ESR_EC_MASK: u64 = 0x3f;

pub const EC_HVC: u64 = 0x16; // HVC instruction execution in AArch64
pub const EC_SMC: u64 = 0x17; // SMC instruction execution in AArch64
pub const EC_MSR_MRS: u64 = 0x18; // trapped MSR, MRS or System instruction
pub const EC_DATA_ABORT_LOWER: u64 = 0x24; // data abort from a lower EL
pub const EC_DATA_ABORT_SAME: u64 = 0x25; // data abort taken without a change in EL

/// Extract the Exception Class from an ESR_EL1 value.
#[inline]
pub fn esr_ec(esr: u64) -> u64 {
    (esr >> ESR_EC_SHIFT) & ESR_EC_MASK
}

/// Extract the low 16 bits of an HVC instruction's immediate from ESR_EL1.
#[inline]
pub fn esr_hvc_imm(esr: u64) -> u16 {
    (esr & 0xffff) as u16
}
