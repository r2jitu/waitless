// `NicOps` POD + link-time registry. Leaf crate so NIC drivers can
// depend here without inheriting the full net stack.

#![no_std]

pub mod error;
pub use error::{DhcpError, NetError, NicError};

use core::sync::atomic::{AtomicPtr, Ordering};

// ---- Core ops --------------------------------------------------------------

/// All fn pointers a NIC driver exposes. A single `&'static NicOps`
/// is published via `AtomicPtr` at boot; every dispatcher call does
/// one Acquire load + one direct call.
///
/// `probe` returns `true` iff the driver bound hardware. It's the
/// only method callers may invoke before bring-up completes; every
/// other call is a no-op / zero until the first probe succeeds.
pub struct NicOps {
    pub name: &'static str,
    pub probe: fn() -> bool,

    // ── Data path ───────────────────────────────────────────────────
    pub send: fn(&[u8]),
    pub poll_rx: fn(fn(&[u8])) -> usize,
    pub poll_qp: fn(usize, fn(&[u8])) -> usize,

    // ── Config / bring-up ───────────────────────────────────────────
    pub get_mac: fn(*mut u8),
    pub num_queue_pairs: fn() -> u16,
    pub activate_multi_queue: fn(),
    pub enable_irq: fn(),
    pub enable_deferred_tx_kick: fn(),

    // ── Per-batch TX flush ──────────────────────────────────────────
    pub flush_tx_staging: fn(),
    pub flush_tx_kick_if_dirty: fn() -> bool,

    // ── Per-cycle interrupt-ack (virtio MMIO ISR) ───────────────────
    pub poke_interrupt_status: fn(),

    // ── Optional capabilities ───────────────────────────────────────
    /// NAPI-style idle hooks. `None` = polling-only driver; the
    /// dispatcher treats `irq_idle_supported` as `false`.
    pub idle: Option<&'static NicIdleOps>,

    /// Per-queue diagnostics. `None` = driver doesn't expose them;
    /// dispatcher returns zero arrays.
    pub diag: Option<&'static NicDiagOps>,
}

/// NAPI-style idle hooks. A driver that implements interrupt-driven
/// idle arms the RX IRQ before WFI / HLT, then checks for pending
/// work on wake.
pub struct NicIdleOps {
    pub arm_rx_interrupts: fn(),
    pub has_pending_rx: fn() -> bool,
    pub has_pending_tx: fn() -> bool,
    pub rearm_rx_napi: fn(u32) -> bool,
}

/// Per-queue diagnostic snapshots. Wired into the stats endpoint but
/// never on the hot path.
pub struct NicDiagOps {
    pub rx_counts: fn() -> [u64; 8],
    pub rx_used_cursors: fn() -> [(u16, u16); 8],
}

// ---- Link-time registry ---------------------------------------------------

/// One entry per linked driver crate, placed in `.uni_drivers_ethernet`
/// by `register_ethernet_driver!`.
#[repr(C)]
pub struct EthernetDriverReg {
    pub ops: &'static NicOps,
}

/// Register a driver with `uni_net` at link time. Expands to a
/// `static EthernetDriverReg` in the `.uni_drivers_ethernet` section;
/// `init()` discovers it via section-boundary symbols.
///
/// ```ignore
/// static MY_OPS: uni_net_driver::NicOps = uni_net_driver::NicOps { /* … */ };
/// uni_net_driver::register_ethernet_driver!(MY_OPS);
/// ```
#[macro_export]
macro_rules! register_ethernet_driver {
    ($ops:expr) => {
        #[used]
        #[unsafe(link_section = ".uni_drivers_ethernet")]
        static ETHERNET_DRIVER_REG: $crate::EthernetDriverReg =
            $crate::EthernetDriverReg { ops: &$ops };
    };
}

// Section-boundary symbols from the linker script. Native hosts have
// no custom script, so `linked_ethernet_drivers()` stubs to `&[]`.
#[cfg(target_os = "none")]
unsafe extern "Rust" {
    static __start_uni_drivers_ethernet: EthernetDriverReg;
    static __stop_uni_drivers_ethernet: EthernetDriverReg;
}

/// All ethernet drivers linked into this binary.
#[cfg(target_os = "none")]
pub fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    // SAFETY: linker guarantees `[start, stop)` is a contiguous
    // run of `EthernetDriverReg` values (the macro is the only
    // writer). Entries live in `.rodata`, materialised at link time.
    unsafe {
        let start = &__start_uni_drivers_ethernet as *const EthernetDriverReg;
        let end = &__stop_uni_drivers_ethernet as *const EthernetDriverReg;
        let count = end.offset_from(start) as usize;
        core::slice::from_raw_parts(start, count)
    }
}

#[cfg(not(target_os = "none"))]
pub fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    &[]
}

// ---- Active driver slot ---------------------------------------------------

// Null-object backstop. `ACTIVE_OPS` points here until the first
// probe succeeds, so every dispatcher call resolves to a real
// `&'static NicOps` without a null check. Hot-path cost per call:
// one Acquire load + one direct fn-pointer call.

fn null_send(_: &[u8]) {}
fn null_poll(_: fn(&[u8])) -> usize { 0 }
fn null_poll_qp(_: usize, _: fn(&[u8])) -> usize { 0 }
fn null_probe() -> bool { false }
fn null_get_mac(_: *mut u8) {}
fn null_num_queue_pairs() -> u16 { 1 }
fn null_void() {}
fn null_false() -> bool { false }

static NULL_OPS: NicOps = NicOps {
    name: "none",
    probe: null_probe,
    send: null_send,
    poll_rx: null_poll,
    poll_qp: null_poll_qp,
    get_mac: null_get_mac,
    num_queue_pairs: null_num_queue_pairs,
    activate_multi_queue: null_void,
    enable_irq: null_void,
    enable_deferred_tx_kick: null_void,
    flush_tx_staging: null_void,
    flush_tx_kick_if_dirty: null_false,
    poke_interrupt_status: null_void,
    idle: None,
    diag: None,
};

static ACTIVE_OPS: AtomicPtr<NicOps> =
    AtomicPtr::new(&NULL_OPS as *const NicOps as *mut NicOps);

/// Install `ops` as the active driver. Called once by `init()` when
/// the first `probe` succeeds.
pub fn set_active_ops(ops: &'static NicOps) {
    ACTIVE_OPS.store(ops as *const _ as *mut _, Ordering::Release);
}

/// Currently-active ops. Returns `NULL_OPS` (all no-ops) before the
/// first successful probe and on native — callers never need to
/// branch on "is a driver installed?". Use `is_installed()` if a
/// cold-path caller genuinely needs to know.
#[inline]
pub fn active_ops() -> &'static NicOps {
    // SAFETY: `ACTIVE_OPS` is always non-null — it starts pointing
    // at `NULL_OPS` and `set_active_ops` only stores pointers
    // derived from `&'static NicOps`. The Release/Acquire pair
    // synchronises store with readers.
    unsafe { &*(ACTIVE_OPS.load(Ordering::Acquire) as *const NicOps) }
}

/// Whether a real driver has been installed. Cold-path — used by
/// `Net::enable` to distinguish "no driver linked" from "drivers
/// linked but none probed".
pub fn is_installed() -> bool {
    !core::ptr::eq(
        ACTIVE_OPS.load(Ordering::Acquire) as *const NicOps,
        &NULL_OPS as *const NicOps,
    )
}
