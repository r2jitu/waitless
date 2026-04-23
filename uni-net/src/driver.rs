// `EthernetDriver` trait + link-time registry. Leaf crate so NIC
// drivers can depend here without inheriting the full net stack.

#![no_std]

pub mod error;
pub use error::{DhcpError, NetError, NicError};

// ---- NicHandle -------------------------------------------------------------

/// Opaque handle for a probed NIC. Multi-device drivers can use it to
/// distinguish instances; single-device drivers treat it as a token.
#[derive(Clone, Copy, Debug)]
pub struct NicHandle {
    _private: (),
}

impl NicHandle {
    pub const fn new() -> Self {
        NicHandle { _private: () }
    }
}

impl Default for NicHandle {
    fn default() -> Self { NicHandle::new() }
}

// ---- EthernetDriver trait -------------------------------------------------

/// The ethernet driver contract. Implementors hand ethernet frames
/// to `uni_net` on RX and accept ethernet frames from `uni_net` on
/// TX. No Waker / async hooks today — a future async executor can
/// grow those on the same type (or a subtrait).
///
/// Intentionally NOT `pub fn init()` + free functions: a trait lets
/// a single `dyn EthernetDriver` sit in the linker section, giving
/// `Net::enable` one call shape to probe and one to dispatch
/// through. Multi-driver apps pay the same indirect-call cost per
/// packet as the current `uni_drivers::net::use_gvnic()` branch, without
/// the hardcoded driver names.
pub trait EthernetDriver: 'static + Sync {
    /// Short identifier used by diagnostics and `boot_info()`. Stable
    /// strings preferred (`"virtio-net"`, `"gve"`).
    fn name(&self) -> &'static str;

    /// Try to bring up the NIC. `None` = this driver doesn't match
    /// the hardware present (e.g. `gve` probing a QEMU host that
    /// doesn't expose a Google NIC). `Net::enable` walks probes in
    /// link order and uses the first success.
    ///
    /// Historically a thin `probe_ok`-flag check that assumed
    /// `uni_drivers::net::init()` had already run. In the Step-6 world
    /// this owns the full bring-up: drivers that `probe()` calls the
    /// device-specific init code, cache success state, and return
    /// `Some` iff the hardware came up. Idempotent — calling twice
    /// returns the cached answer.
    fn probe(&self) -> Option<NicHandle>;

    /// Transmit one ethernet frame. Returns `NicError::TxQueueFull`
    /// when the caller should retry later. Current drivers (virtio-
    /// net, gve) don't surface TX-full back-pressure — they stage
    /// into a per-core ring when the queue is busy — so the impl
    /// always returns `Ok(())`. The `Result` keeps the signature
    /// future-proof for async-aware drivers in §2g.
    fn send(&self, handle: &NicHandle, frame: &[u8]) -> Result<(), NicError>;

    /// Drain any received frames, invoking `cb` once per frame.
    /// Returns the number of frames delivered. Zero means "no RX
    /// pending right now" — the caller should go idle.
    ///
    /// `cb` is a plain `fn(&[u8])` (not `&mut dyn FnMut`) to match
    /// the existing `uni_drivers::net::poll` / `poll_qp` shape and
    /// avoid adapter boilerplate on the hot path. Closures that
    /// capture state can still dispatch through a static — that's
    /// what `net::net_receive` does today.
    fn poll_rx(&self, handle: &NicHandle, cb: fn(&[u8])) -> usize;

    // ── Extended dispatcher methods ─────────────────────────────────────
    //
    // These mirror the `uni_drivers::net::*` API surface so `drivers/net.rs`
    // can dispatch through the trait instead of statically linking both
    // NIC crates. Defaults are no-ops (`false` / `[0; _]` / empty MAC)
    // for polling-only / single-queue drivers; virtio overrides most,
    // gve inherits most defaults.

    /// Fill the 6-byte MAC into `out`. Default writes 00:00:00:00:00:00.
    fn get_mac(&self, _handle: &NicHandle, _out: *mut u8) {}

    /// Active queue pairs after bring-up. Default 1 (single-queue).
    fn num_queue_pairs(&self, _handle: &NicHandle) -> u16 { 1 }

    /// Negotiate multi-queue. Default no-op (drivers with their own
    /// MQ setup at init, like gve, don't need this hook).
    fn activate_multi_queue(&self, _handle: &NicHandle) {}

    /// Install MSI-X or equivalent interrupt wiring. Default no-op
    /// for polling-only drivers.
    fn enable_irq(&self, _handle: &NicHandle) {}

    /// Poll a specific queue pair. Default routes to `poll_rx` — fine
    /// for single-queue drivers. Multi-queue drivers override.
    fn poll_qp(&self, handle: &NicHandle, _qp: usize, cb: fn(&[u8])) -> i32 {
        self.poll_rx(handle, cb) as i32
    }

    /// Flush staged TX packets. Default no-op (no staging pool).
    fn flush_tx_staging(&self, _handle: &NicHandle) {}

    /// Kick TX if any queue has dirty doorbell state. Default false.
    fn flush_tx_kick_if_dirty(&self, _handle: &NicHandle) -> bool { false }

    /// NAPI-style idle supported? Default false.
    fn irq_idle_supported(&self, _handle: &NicHandle) -> bool { false }

    /// Arm RX-pending interrupt before idle. Default no-op.
    fn arm_rx_interrupts(&self, _handle: &NicHandle) {}

    /// RX pending right now? Default false (polling always works).
    fn has_pending_rx(&self, _handle: &NicHandle) -> bool { false }

    /// TX pending right now? Default false.
    fn has_pending_tx(&self, _handle: &NicHandle) -> bool { false }

    /// NAPI re-arm, per-core. Default false.
    fn rearm_rx_napi(&self, _handle: &NicHandle, _core_id: u32) -> bool { false }

    /// Enable deferred TX kick optimisation. Default no-op.
    fn enable_deferred_tx_kick(&self, _handle: &NicHandle) {}

    /// Poke interrupt status (virtio MMIO ISR ack). Default no-op.
    fn poke_interrupt_status(&self, _handle: &NicHandle) {}

    /// Per-queue RX frame counts. Default all zeros.
    fn rx_counts(&self, _handle: &NicHandle) -> [u64; 8] { [0; 8] }

    /// Per-queue `(device_idx, driver_cursor)` snapshots. Default zeros.
    fn rx_used_cursors(&self, _handle: &NicHandle) -> [(u16, u16); 8] { [(0, 0); 8] }
}

// ---- Link-time registry ---------------------------------------------------

/// A link-time driver registration. One instance per linked driver
/// crate, placed in the `.uni_drivers_ethernet` section by
/// `register_ethernet_driver!`.
#[repr(C)]
pub struct EthernetDriverReg {
    /// Implementation placed behind a `&'static dyn` so the
    /// registration entry has a known layout (fat pointer: vtable
    /// + data, both pointer-sized). ALIGN(8) in the linker script
    /// matches that layout.
    pub driver: &'static dyn EthernetDriver,
}

/// Register a driver with `uni_net` at link time. Expands to a
/// `static` in the `.uni_drivers_ethernet` section, which
/// `Net::enable` discovers via the section-boundary symbols.
///
/// Usage inside a driver crate:
///
/// ```ignore
/// struct VirtioNetDriver;
/// impl uni_net_driver::EthernetDriver for VirtioNetDriver { /* ... */ }
/// static DRIVER: VirtioNetDriver = VirtioNetDriver;
/// uni_net_driver::register_ethernet_driver!(DRIVER);
/// ```
///
/// Driver crates that prefer the `uni_net::…` re-export can write
/// `uni_net::register_ethernet_driver!(DRIVER)` — both resolve to
/// the same macro.
#[macro_export]
macro_rules! register_ethernet_driver {
    ($driver:expr) => {
        #[used]
        #[unsafe(link_section = ".uni_drivers_ethernet")]
        static ETHERNET_DRIVER_REG: $crate::EthernetDriverReg =
            $crate::EthernetDriverReg { driver: &$driver };
    };
}

// Section-boundary symbols, provided by the linker script for every
// unikernel target. On native hosts these don't exist (no custom
// linker script), so the `linked_ethernet_drivers()` accessor always
// returns an empty slice there — matches the reality that native
// doesn't use ethernet drivers at all.
#[cfg(target_os = "none")]
unsafe extern "Rust" {
    static __start_uni_drivers_ethernet: EthernetDriverReg;
    static __stop_uni_drivers_ethernet: EthernetDriverReg;
}

/// All ethernet drivers linked into this binary. Empty if no
/// `uni-driver-*` crate is in the dep graph (compute-only apps). One
/// `unsafe` block — every other step of the registration mechanism
/// is safe Rust.
#[cfg(target_os = "none")]
pub fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    // SAFETY: the linker guarantees `__start_*` ≤ `__stop_*` and
    // that `[start, stop)` is a contiguous run of `EthernetDriverReg`
    // values (the registration macro is the only writer of the
    // section, and it only emits `EthernetDriverReg` statics). Each
    // entry is fully initialised before boot code runs, because
    // `#[used]` + `#[link_section]` statics live in `.rodata` and
    // are materialised at link time, not at runtime.
    unsafe {
        let start = &__start_uni_drivers_ethernet as *const EthernetDriverReg;
        let end = &__stop_uni_drivers_ethernet as *const EthernetDriverReg;
        let count = end.offset_from(start) as usize;
        core::slice::from_raw_parts(start, count)
    }
}

/// Native builds have no linker section, so always return empty.
/// Apps on native reach the network through POSIX sockets, not
/// ethernet drivers.
#[cfg(not(target_os = "none"))]
pub fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    &[]
}

// ---- Active driver slot ---------------------------------------------------
//
// Filled once by the first `probe()`-successful driver during
// `uni_drivers::net::init()` (or, on native, never). `drivers/net.rs`
// dispatches through `active_driver()` instead of calling specific
// NIC crates statically, which lets `//drivers:drivers` drop its
// direct deps on the NIC crates and lets apps pick their driver set.

use core::sync::atomic::{AtomicPtr, Ordering};

static ACTIVE_DRIVER: AtomicPtr<EthernetDriverReg> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install `reg` as the active driver. Called once by
/// `uni_drivers::net::init()` (first successful probe wins).
pub fn set_active_driver(reg: &'static EthernetDriverReg) {
    ACTIVE_DRIVER.store(reg as *const _ as *mut _, Ordering::Release);
}

/// Return the currently-active ethernet driver, if any. Returns
/// `None` before the first `probe()` success and on native (no
/// linker section → nothing to set).
pub fn active_driver() -> Option<&'static dyn EthernetDriver> {
    let p = ACTIVE_DRIVER.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: `set_active_driver` only stores pointers to
        // `&'static EthernetDriverReg` values from the linker
        // section; the Release/Acquire pair above synchronises the
        // store with readers. Pointer is never reused or freed.
        unsafe { Some((*(p as *const EthernetDriverReg)).driver) }
    }
}
