// uni-net/lib.rs — net-stack crate.
//
// Carved out of `uni::net` (the module) so driver crates
// (`uni-driver-virtio-net`, `uni-driver-gve` in Phase 5 Step 3+)
// can implement `EthernetDriver` without creating a `drivers → uni`
// dep cycle. Apps still reach the same surface via `uni::net::*`
// and `uni::{NetError, DhcpError, NicError}` — `uni/lib.rs` re-
// exports this crate unchanged so no app-side imports move.
//
// Layout:
//   * `error` module — NetError / DhcpError / NicError + From
//     chain. Shared with driver crates (`NicError`) and boot code
//     (`NetError`). Standalone-testable.
//   * `Net::enable` API — Phases 3/4.
//   * `EthernetDriver` trait + `register_ethernet_driver!` macro
//     + `linked_ethernet_drivers()` walker — Phase 5 Step 1.
//
// On native the bring-up path is a no-op: POSIX sockets come
// pre-configured. Only the umbrella's `tls_server` is pulled in
// (for the hand-rolled TLS 1.3 state machine shared across both
// platforms).

#![no_std]

// `alloc` for Box<Net> in the module-level slot.
extern crate alloc;

// ---- Umbrella re-export ---------------------------------------------------
//
// Bare-metal side pulls the full `net` umbrella (tcp/udp/arp/ipv4/
// tls_server/types/…); native pulls just `net_tls_server` for the
// hand-rolled TLS state machine. Re-exported publicly at the
// crate root so `uni/http.rs` can keep writing
// `net::tls_server::X` / `net::tcp::X` via the `uni::net` alias in
// `uni/lib.rs`.

#[cfg(platform_unikernel)]
extern crate net as net_umbrella;

#[cfg(platform_unikernel)]
pub use net_umbrella::*;

#[cfg(platform_native)]
extern crate net_tls_server as net_tls_server_impl;

#[cfg(platform_native)]
pub mod tls_server {
    pub use crate::net_tls_server_impl::*;
}

// ---- Error types ----------------------------------------------------------

pub mod error;
pub use error::{DhcpError, NetError, NicError};

// ---- Public net-stack API -------------------------------------------------

use core::cell::UnsafeCell;

/// IPv4 octets, network-order storage. Defined locally (rather than
/// re-exported from `net_types`) so the API compiles on both
/// `platform_unikernel` and `platform_native`. The bare-metal
/// backend converts via the private `to_net_ipv4` helper below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const UNSPECIFIED: Ipv4Addr = Ipv4Addr([0, 0, 0, 0]);

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr([a, b, c, d])
    }
}

/// How the network stack should come up at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetBringUp {
    /// Negotiate an address via DHCP. Blocks up to ~10 s; returns
    /// `NetError::Dhcp(_)` if the server doesn't answer. Typical
    /// for cloud deployments (GCE, AWS, Azure) and QEMU/HVF user
    /// networking, all of which run a DHCP server by default.
    Dhcp,

    /// Skip DHCP and apply the supplied IPv4 config directly.
    /// Used when the deployment environment has no DHCP server
    /// (tap-mode KVM, minimal hypervisors) or to pin an address
    /// for reproducibility in benchmarks.
    Static {
        ip: Ipv4Addr,
        gateway: Ipv4Addr,
        netmask: Ipv4Addr,
    },
}

/// Opaque handle returned by `Net::enable`. Phase 4 wires the real
/// storage (a `Box<Net>` parked in the module-level `NET` slot);
/// future phases grow per-subsystem fields onto this type.
///
/// Zero-sized today, so copying the handle around is free. The
/// private field prevents users from synthesising one without going
/// through `enable`.
pub struct Net {
    _private: (),
}

// ---- NET slot --------------------------------------------------------------
//
// Mirrors the `APP_SLOT` pattern in `uni/lib.rs`: a single static
// holding `Option<Box<Net>>`, written only on the boot CPU, cleared
// only from `uni::shutdown_and_drop` (also BSP).

struct NetSlot(UnsafeCell<Option<alloc::boxed::Box<Net>>>);

impl NetSlot {
    const fn empty() -> Self {
        NetSlot(UnsafeCell::new(None))
    }
}

// SAFETY: every read/write of `NET` is on the boot CPU:
//   - `Net::enable` runs from `uni_main` (BSP on unikernel, main
//     thread on native).
//   - `clear_on_shutdown` runs from `uni::shutdown_and_drop`, called
//     only from the BSP shutdown branch of the kernel event loop.
unsafe impl Sync for NetSlot {}

static NET: NetSlot = NetSlot::empty();

impl Net {
    /// Bring the network stack online. On success stores a
    /// `Box<Net>` in the module-level slot and returns a handle.
    ///
    /// Failure semantics: the slot is **not** populated on failure,
    /// so apps can retry with a different config. The typical
    /// pattern is `enable(Dhcp).or_else(|_| enable(Static{…}))`.
    ///
    /// Calling `enable` twice after a successful bring-up returns
    /// `Err(NetError::AlreadyEnabled)`.
    pub fn enable(cfg: NetBringUp) -> Result<Net, NetError> {
        // SAFETY: BSP-only access; see `unsafe impl Sync for NetSlot`.
        if unsafe { (*NET.0.get()).is_some() } {
            return Err(NetError::AlreadyEnabled);
        }
        bringup(cfg)?;
        // Park a `Box<Net>` in the slot so `is_enabled()` reflects
        // "someone successfully called enable". The returned handle
        // is a separate ZST — both are free to pass around.
        // SAFETY: BSP-only access.
        unsafe {
            *NET.0.get() = Some(alloc::boxed::Box::new(Net { _private: () }));
        }
        Ok(Net { _private: () })
    }

    /// Our configured IPv4 address. Returns `UNSPECIFIED` if the
    /// stack came up but neither DHCP nor the static config
    /// actually produced one (shouldn't happen under normal
    /// config; present for symmetry with Phase-8 Net APIs).
    pub fn local_ip(&self) -> Ipv4Addr {
        #[cfg(platform_unikernel)]
        {
            let o = crate::types::CONFIG.ip().octets();
            Ipv4Addr(o)
        }
        #[cfg(platform_native)]
        {
            // Native runs over POSIX sockets — we don't manage
            // the interface address. Return UNSPECIFIED so apps
            // can't depend on it.
            Ipv4Addr::UNSPECIFIED
        }
    }
}

/// Whether the stack is currently enabled (the slot holds a `Box<Net>`).
pub fn is_enabled() -> bool {
    // SAFETY: BSP-only access; see `unsafe impl Sync for NetSlot`.
    unsafe { (*NET.0.get()).is_some() }
}

/// Clear the NET slot. Called from `uni::shutdown_and_drop` on the
/// graceful-shutdown path so a re-entrant runtime (native's
/// `main` → rerun) sees a fresh slot. Idempotent.
pub fn clear_on_shutdown() {
    // SAFETY: BSP-only; see the slot's `unsafe impl Sync`. `take`
    // replaces with `None`, dropping the Box (ZST alloc = no-op).
    let taken = unsafe { (*NET.0.get()).take() };
    drop(taken);
}

// ----------------------------------------------------------------------------
// Backend dispatch — unikernel vs native
// ----------------------------------------------------------------------------

#[cfg(platform_unikernel)]
fn bringup(cfg: NetBringUp) -> Result<(), NetError> {
    match cfg {
        NetBringUp::Dhcp => {
            if net_umbrella::bringup_dhcp() {
                Ok(())
            } else {
                // No implicit static fallback — surfacing the
                // timeout lets callers decide whether to retry
                // with `NetBringUp::Static{…}` or panic.
                Err(NetError::Dhcp(DhcpError::Timeout))
            }
        }
        NetBringUp::Static { ip, gateway, netmask } => {
            net_umbrella::bringup_static(
                to_net_ipv4(ip),
                to_net_ipv4(gateway),
                to_net_ipv4(netmask),
            );
            Ok(())
        }
    }
}

#[cfg(platform_native)]
fn bringup(_cfg: NetBringUp) -> Result<(), NetError> {
    // The native backend runs over POSIX sockets; the host
    // manages interface configuration. `Net::enable` is
    // essentially a typed hand-off: the slot lets forward-compat
    // code distinguish explicit vs implicit bring-up (there is no
    // implicit path post-Phase-4).
    Ok(())
}

/// `uni_net::Ipv4Addr` → bare-metal `net_types::Ipv4Addr`. Kept as a
/// standalone helper rather than a `From` impl so we don't need a
/// cross-crate orphan dance.
#[cfg(platform_unikernel)]
fn to_net_ipv4(a: Ipv4Addr) -> net_umbrella::types::Ipv4Addr {
    let [o0, o1, o2, o3] = a.0;
    net_umbrella::types::Ipv4Addr::from(o0, o1, o2, o3)
}

// ============================================================================
// Phase 5: ethernet driver registration mechanism
// ============================================================================
//
// Drivers register at LINK time via `register_ethernet_driver!`, which
// emits one `EthernetDriverReg` into the `.uni_drivers_ethernet`
// section. The kernel discovers linked drivers by walking
// `[__start_uni_drivers_ethernet, __stop_uni_drivers_ethernet)` at
// boot. Zero runtime registration overhead; "no driver linked" is an
// empty section and walks to an empty slice (no probe, no call).

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
    /// crates (which live outside `uni_net`) can return handles.
    pub const fn new() -> Self {
        NicHandle { _private: () }
    }
}

impl Default for NicHandle {
    fn default() -> Self { NicHandle::new() }
}

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
    /// when the caller should retry later.
    fn send(&self, handle: &NicHandle, frame: &[u8]) -> Result<(), NicError>;

    /// Drain any received frames, invoking `cb` once per frame.
    /// Returns the number of frames delivered. Zero means "no RX
    /// pending right now" — the caller should go idle.
    fn poll_rx(&self, handle: &NicHandle, cb: &mut dyn FnMut(&[u8])) -> usize;
}

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
/// impl uni_net::EthernetDriver for VirtioNetDriver { /* ... */ }
/// static DRIVER: VirtioNetDriver = VirtioNetDriver;
/// uni_net::register_ethernet_driver!(DRIVER);
/// ```
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
