// uni/net.rs — `Net::enable` API (Phases 3 + 4).
//
// Apps call `Net::enable(NetBringUp::Dhcp)` (or `Static { … }`) at
// startup to bring the network stack online. After Phase 4 there is
// no boot-path fallback: an app that doesn't call `enable` gets no
// network. This mirrors `uni::run`: explicit, typed, app-driven.
//
// State shape:
//
//   static NET: NetSlot = NetSlot::empty();
//
// On success `enable` allocates a `Box<Net>` and parks it in the
// slot. Subsequent `enable` calls see `Some(_)` and return
// `Err(NetError::AlreadyEnabled)`. `uni::shutdown_and_drop` clears
// the slot on graceful exit, symmetric with the `App` slot.
//
// Net is zero-sized today. Phase 5/6 carve out `uni-net` as a
// standalone crate and that's when fields like `config`,
// `udp_handlers`, `dhcp_state`, `dispatcher` move in — touching them
// now would need the protocol sub-crates to depend on `uni::net`,
// which inverts the current dep graph. The slot shape is already in
// place so the field additions are a focused follow-up rather than a
// whole-tree reshape.

use core::cell::UnsafeCell;

pub use crate::error::{DhcpError, NetError, NicError};

// Re-export the umbrella crate's contents (TCP, UDP, TLS server,
// types, …) under `crate::net::*` for internal `uni::*` consumers
// only. Keeps `uni/http.rs` and the backend module in `uni/lib.rs`
// writing `net::tls_server::X` / `net::tcp::X` unchanged.
pub(crate) use crate::net_umbrella::*;

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
// only from `uni::shutdown_and_drop` (also BSP). `Box<Net>` for a
// zero-sized `Net` doesn't allocate — `Box` uses a dangling pointer
// for ZSTs — so the slot is currently "presence/absence" only.

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
// Manual `Sync` lets the static hold it without requiring
// `Box<Net>: Sync` (there are no inner fields today, but future
// additions shouldn't force a `Send + Sync` bound on every field).
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
        // Park a `Box<Net>` in the slot so `is_some()` reflects
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
            let o = crate::net_umbrella::types::CONFIG.ip().octets();
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
/// Phase 4+ this is the single source of truth; Phase 3's legacy
/// auto-init fallback has been removed.
pub fn is_enabled() -> bool {
    // SAFETY: BSP-only access; see `unsafe impl Sync for NetSlot`.
    unsafe { (*NET.0.get()).is_some() }
}

/// Clear the NET slot. Called from `uni::shutdown_and_drop` on the
/// graceful-shutdown path so a re-entrant runtime (native's
/// `main` → rerun) sees a fresh slot. Idempotent.
pub(crate) fn clear_on_shutdown() {
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
            if crate::net_umbrella::bringup_dhcp() {
                Ok(())
            } else {
                // No implicit static fallback — surfacing the
                // timeout lets callers decide whether to retry
                // with `NetBringUp::Static{…}` or panic.
                Err(NetError::Dhcp(DhcpError::Timeout))
            }
        }
        NetBringUp::Static { ip, gateway, netmask } => {
            crate::net_umbrella::bringup_static(
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

/// `uni::net::Ipv4Addr` → bare-metal `net_types::Ipv4Addr`. Kept as
/// a standalone helper rather than a `From` impl so we don't need a
/// cross-crate orphan dance (the two types live in different crates).
#[cfg(platform_unikernel)]
fn to_net_ipv4(a: Ipv4Addr) -> crate::net_umbrella::types::Ipv4Addr {
    let [o0, o1, o2, o3] = a.0;
    crate::net_umbrella::types::Ipv4Addr::from(o0, o1, o2, o3)
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
//
// Phase 5 Step 1 (this commit) wires the trait, macro, walker, and
// linker-script section. Steps 2–4 migrate `drivers/virtio_net.rs`
// and `drivers/gvnic.rs` onto the trait; Phase 5 as a whole closes
// with each driver in its own `uni-driver-*` crate.

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
    /// crates (which live outside `uni::net`) can return handles.
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
/// impl uni::net::EthernetDriver for VirtioNetDriver { /* ... */ }
/// static DRIVER: VirtioNetDriver = VirtioNetDriver;
/// uni::net::register_ethernet_driver!(DRIVER);
/// ```
///
/// The macro references `$crate::net::EthernetDriverReg`, which
/// resolves to `uni::net::EthernetDriverReg` when the macro is
/// re-exported at the crate root (Phase 5 Step 4 will add that
/// re-export once driver crates land outside `uni`).
#[macro_export]
macro_rules! register_ethernet_driver {
    ($driver:expr) => {
        #[used]
        #[unsafe(link_section = ".uni_drivers_ethernet")]
        static ETHERNET_DRIVER_REG: $crate::net::EthernetDriverReg =
            $crate::net::EthernetDriverReg { driver: &$driver };
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
