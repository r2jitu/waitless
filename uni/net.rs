// uni/net.rs — Phase 3 `Net::enable` API.
//
// Apps call `Net::enable(NetBringUp::Dhcp)` (or `Static { … }`) at
// startup to bring the network stack online explicitly. Existing
// code that doesn't call it still works: `boot/entry.rs` runs an
// auto-init fallback (DHCP) after `uni_main` returns unless
// `Net::enable` was already called.
//
// Phase 4 removes the fallback and promotes `Net::enable` from
// "forward-compat" to the only bring-up path. Phases 5/6 carve out
// `uni-net` as a dedicated crate; this module becomes that crate's
// `lib.rs` at that point. Until then `Net` is a module inside `uni`
// to avoid adding a new crate ahead of need.

use core::sync::atomic::{AtomicBool, Ordering};

pub use crate::error::{NetError, DhcpError};

// Re-export the umbrella crate's contents (TCP, UDP, TLS server,
// types, …) under `crate::net::*` for internal `uni::*` consumers
// only. Keeps `uni/http.rs` and the backend module in `uni/lib.rs`
// writing `net::tls_server::X` / `net::tcp::X` unchanged. The
// re-export is `pub(crate)` so external apps don't see it — they
// interact with networking through the curated `Net::enable`,
// `Ipv4Addr`, `NetBringUp` surface defined below. Phase 5 replaces
// this module with a standalone `uni-net` crate; the narrow
// re-export gives us a single namespace to carve out.
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

/// Opaque handle returned by `Net::enable`. Holding one signals
/// "the app has brought up the stack explicitly" — used by the
/// boot path's auto-init fallback check (see `was_enabled`).
///
/// Phase 4 will attach fields (config, dispatcher, UDP handlers)
/// to this type. For now it's zero-sized so apps can hand it
/// around freely without worrying about ownership semantics.
pub struct Net {
    // Private field so users can't synthesize a `Net` without
    // calling `enable` (which is the thing that sets the flag).
    _private: (),
}

/// Flag observed by `boot/entry.rs` after `uni_main` returns to
/// decide whether to run the DHCP fallback. Set by `Net::enable`;
/// never cleared.
static ENABLED: AtomicBool = AtomicBool::new(false);

impl Net {
    /// Bring the network stack online. On success returns an opaque
    /// handle whose presence signals "the app drove bring-up"; the
    /// boot-path auto-init fallback is skipped after a successful
    /// `enable`. On failure the ENABLED flag is left clear so apps
    /// can retry with a different config (typical pattern:
    /// `enable(Dhcp).or_else(|_| enable(Static{…}))`).
    ///
    /// Subsequent calls after a successful `enable` return
    /// `Err(NetError::AlreadyEnabled)` — a second bring-up would
    /// be a misuse.
    pub fn enable(cfg: NetBringUp) -> Result<Net, NetError> {
        if ENABLED.load(Ordering::Acquire) {
            return Err(NetError::AlreadyEnabled);
        }
        bringup(cfg)?;
        // Commit the flag only after bring-up succeeded — a failed
        // DHCP shouldn't lock out a Static retry.
        ENABLED.store(true, Ordering::Release);
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

/// Whether `Net::enable` has been called. Consulted by the boot
/// path's auto-init fallback; should not be used by app code.
#[doc(hidden)]
pub fn was_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Mark `Net` as enabled WITHOUT going through the public `enable`
/// path. Called by the boot-path auto-init fallback so a later
/// `Net::enable` returns `AlreadyEnabled` rather than re-running
/// DHCP. Not part of the public API.
#[doc(hidden)]
pub fn mark_enabled_by_auto_init() {
    ENABLED.store(true, Ordering::Release);
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
                // with `NetBringUp::Static{…}` or panic. The
                // legacy auto-init path in `boot/entry.rs` still
                // does its own DHCP-then-10.0.2.15/24 fallback
                // for apps that don't call `Net::enable` at all.
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
    // essentially a typed hand-off: the flag lets forward-compat
    // code (Phase 4+) distinguish explicit vs implicit bring-up.
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
