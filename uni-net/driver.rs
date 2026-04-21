// uni-net/driver.rs — Ethernet driver contract + link-time registry.
//
// `lib.rs` of the leaf `uni_net_driver` crate. Includes `error.rs`
// as a submodule so the `NetError` / `DhcpError` / `NicError`
// hierarchy is reachable from driver crates without pulling the
// full `uni_net` stack.
//
// Sits as its own tiny leaf crate so that driver crates like
// `drivers` can depend on it without the cycle that would appear
// otherwise:
//
//     drivers → uni_net → net (umbrella) → drivers
//
// `uni_net` re-exports everything from here so app-facing imports
// like `use uni_net::EthernetDriver` keep working.

#![no_std]

pub mod error;
pub use error::{DhcpError, NetError, NicError};

// ---- NicHandle -------------------------------------------------------------

/// Opaque handle identifying a successfully-probed NIC. Drivers that
/// support multiple NIC instances can use it to distinguish them;
/// single-NIC drivers can treat it as a presence token.
#[derive(Clone, Copy, Debug)]
pub struct NicHandle {
    _private: (),
}

impl NicHandle {
    /// Construct a handle. Meant for driver `probe()` implementations;
    /// framework code never constructs one directly. `pub` so driver
    /// crates (which live outside this one) can return handles.
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
/// TX. Phase 5 doesn't add Waker / async hooks — §2g's executor will
/// grow those on the same type (or a subtrait) when it knows what it
/// needs.
///
/// Intentionally NOT `pub fn init()` + free functions: a trait lets
/// a single `dyn EthernetDriver` sit in the linker section, giving
/// `Net::enable` one call shape to probe and one to dispatch
/// through. Multi-driver apps pay the same indirect-call cost per
/// packet as the current `drivers::net::use_gvnic()` branch, without
/// the hardcoded driver names.
pub trait EthernetDriver: 'static + Sync {
    /// Short identifier used by diagnostics and `boot_info()`. Stable
    /// strings preferred (`"virtio-net"`, `"gve"`).
    fn name(&self) -> &'static str;

    /// Try to bring up the NIC. `None` = this driver doesn't match
    /// the hardware present (e.g. `gve` probing a QEMU host that
    /// doesn't expose a Google NIC). `Net::enable` walks probes in
    /// link order and uses the first success.
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
    /// the existing `drivers::net::poll` / `poll_qp` shape and
    /// avoid adapter boilerplate on the hot path. Closures that
    /// capture state can still dispatch through a static — that's
    /// what `net::net_receive` does today.
    fn poll_rx(&self, handle: &NicHandle, cb: fn(&[u8])) -> usize;
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
// unikernel target. On `platform_native` these don't exist (no custom
// linker script), so the `linked_ethernet_drivers()` accessor always
// returns an empty slice there — matches the reality that native
// doesn't use ethernet drivers at all.
#[cfg(platform_unikernel)]
unsafe extern "Rust" {
    static __start_uni_drivers_ethernet: EthernetDriverReg;
    static __stop_uni_drivers_ethernet: EthernetDriverReg;
}

/// All ethernet drivers linked into this binary. Empty if no
/// `uni-driver-*` crate is in the dep graph (compute-only apps). One
/// `unsafe` block — every other step of the registration mechanism
/// is safe Rust.
#[cfg(platform_unikernel)]
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
#[cfg(platform_native)]
pub fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    &[]
}
