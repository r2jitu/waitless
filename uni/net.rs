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

pub use crate::error::{NetError, DhcpError};

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
