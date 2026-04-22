// uni-net/lib.rs — net-stack crate.
//
// Carved out of `uni::net` (the module) so driver crates can
// implement `EthernetDriver` without creating a `drivers → uni`
// dep cycle. Apps still reach the same surface via `uni::net::*`
// and `uni::{NetError, DhcpError, NicError}` — `uni/lib.rs` re-
// exports this crate unchanged so no app-side imports move.
//
// Layout:
//   * `uni_net_driver` (leaf crate) — the driver contract
//     (EthernetDriver trait, NicHandle, error types,
//     registration macro, section walker). Split out so driver
//     crates depend on it without inheriting the full net stack.
//     Re-exported from this crate's root.
//   * `Net::enable` API — Phases 3/4, lives in this file.
//   * Umbrella re-export — brings tcp/udp/arp/ipv4/tls_server from
//     the bare-metal `net` umbrella, or just `tls_server` on native.

#![no_std]

// `alloc` for Box<Net> in the module-level slot.
extern crate alloc;

// Re-export the driver API (trait + macro + walker + errors +
// NicHandle) so `uni_net::EthernetDriver` and friends resolve
// unchanged. The leaf crate owns the definitions.
extern crate uni_net_driver;
pub use uni_net_driver::{
    linked_ethernet_drivers, DhcpError, EthernetDriver, EthernetDriverReg, NetError,
    NicError, NicHandle,
};

// Re-export the registration macro at this crate root too. Apps /
// driver crates that depend on `uni_net` can write
// `uni_net::register_ethernet_driver!(…)` instead of reaching for
// `uni_net_driver`.
pub use uni_net_driver::register_ethernet_driver;

// ---- Umbrella re-export ---------------------------------------------------
//
// Bare-metal side pulls the full `net` umbrella (tcp/udp/arp/ipv4/
// tls_server/types/…); native pulls just `net_tls_server` for the
// hand-rolled TLS state machine. Re-exported publicly at the
// crate root so `uni/http.rs` can keep writing
// `net::tls_server::X` / `net::tcp::X` via the `uni::net` alias in
// `uni/lib.rs`.

#[cfg(target_os = "none")]
extern crate net as net_umbrella;

#[cfg(target_os = "none")]
pub use net_umbrella::*;

#[cfg(not(target_os = "none"))]
extern crate net_tls_server as net_tls_server_impl;

#[cfg(not(target_os = "none"))]
pub mod tls_server {
    pub use crate::net_tls_server_impl::*;
}

// ---- Public net-stack API -------------------------------------------------

use core::cell::UnsafeCell;

/// IPv4 octets, network-order storage. Defined locally (rather than
/// re-exported from `net_types`) so the API compiles on both the
/// bare-metal (`target_os = "none"`) and native backends. The
/// bare-metal backend converts via the private `to_net_ipv4` helper
/// below.
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

        // Phase 5 Step 5: validate that a driver registered via
        // `register_ethernet_driver!` is linked AND has probed
        // successfully. Returns `NoDriver` if the binary has no
        // driver crate linked at all (empty linker section) and
        // `NoNic` if drivers are linked but none bound hardware.
        //
        // On bare-metal today the legacy `drivers::net::init()`
        // path in `boot/entry.rs` runs before `uni_main` and sets
        // each driver's `probe_ok` flag; our `probe()` impls
        // surface that flag. Phase 5 Step 6 (future) will remove
        // the legacy init and have `probe()` own the full device
        // bring-up.
        //
        // Native builds skip this check — `linked_ethernet_drivers()`
        // is stubbed to `&[]` there and networking flows through
        // POSIX sockets, not ethernet drivers.
        #[cfg(target_os = "none")]
        {
            let drivers = uni_net_driver::linked_ethernet_drivers();
            if drivers.is_empty() {
                return Err(NetError::NoDriver);
            }
            let mut any_probed = false;
            for reg in drivers {
                if reg.driver.probe().is_some() {
                    any_probed = true;
                    break;
                }
            }
            if !any_probed {
                return Err(NetError::NoNic);
            }
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
        #[cfg(target_os = "none")]
        {
            let o = crate::types::CONFIG.ip().octets();
            Ipv4Addr(o)
        }
        #[cfg(not(target_os = "none"))]
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

#[cfg(target_os = "none")]
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

#[cfg(not(target_os = "none"))]
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
#[cfg(target_os = "none")]
fn to_net_ipv4(a: Ipv4Addr) -> net_umbrella::types::Ipv4Addr {
    let [o0, o1, o2, o3] = a.0;
    net_umbrella::types::Ipv4Addr::from(o0, o1, o2, o3)
}
