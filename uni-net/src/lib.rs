// `Net::enable` API + re-exports. The `NicOps` POD + link-time
// registry live in the sibling `uni_net_driver` leaf crate so NIC
// drivers can depend there without forming a `drivers → uni` cycle.

#![no_std]

extern crate alloc;

extern crate uni_net_driver;
pub use uni_net_driver::{
    linked_ethernet_drivers, register_ethernet_driver, DhcpError, EthernetDriverReg,
    NetError, NicError, NicDiagOps, NicIdleOps, NicOps,
};

// Bare-metal pulls the full net umbrella; native uses POSIX sockets.
#[cfg(target_os = "none")]
pub use uni_net_stack::*;

// ---- Public net-stack API -------------------------------------------------

use core::cell::UnsafeCell;

/// IPv4 octets in network order. Defined here rather than re-exported
/// from `net_types` so the type works on both bare-metal and native.
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

/// Opaque handle returned by `Net::enable`. Backed by a `Box<Net>`
/// parked in the module-level `NET` slot.
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
//   - `Net::enable` runs from `uni_boot` (BSP on unikernel, main
//     thread on native).
//   - `clear_on_shutdown` runs from `uni::shutdown_and_drop`, called
//     only from the BSP shutdown branch of the kernel event loop.
unsafe impl Sync for NetSlot {}

static NET: NetSlot = NetSlot::empty();

impl Net {
    /// Bring the network stack online. On success stores a
    /// `Box<Net>` in the module-level slot and returns a handle.
    ///
    /// Async so DHCP (bare-metal) can yield between DISCOVER/REQUEST
    /// and OFFER/ACK while the event-loop TX-flush hook fires between
    /// polls. Native's body trivially resolves on first poll (nothing
    /// to wait on — POSIX sockets don't need DHCP).
    ///
    /// Failure semantics: the slot is **not** populated on failure,
    /// so apps can retry with a different config. Typical pattern:
    /// `match Net::enable(Dhcp).await { Ok(n) => n, Err(_) =>
    /// Net::enable(Static {..}).await.expect(..) }`.
    ///
    /// Calling `enable` twice after a successful bring-up returns
    /// `Err(NetError::AlreadyEnabled)`.
    pub async fn enable(cfg: NetBringUp) -> Result<Net, NetError> {
        // SAFETY: BSP-only access; see `unsafe impl Sync for NetSlot`.
        if unsafe { (*NET.0.get()).is_some() } {
            return Err(NetError::AlreadyEnabled);
        }

        #[cfg(target_os = "none")]
        {
            let drivers = uni_net_driver::linked_ethernet_drivers();
            if drivers.is_empty() {
                return Err(NetError::NoDriver);
            }
            let mut any_probed = false;
            for reg in drivers {
                if (reg.ops.probe)() {
                    any_probed = true;
                    break;
                }
            }
            if !any_probed {
                return Err(NetError::NoNic);
            }
        }

        bringup(cfg).await?;

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
async fn bringup(cfg: NetBringUp) -> Result<(), NetError> {
    match cfg {
        NetBringUp::Dhcp => {
            if uni_net_stack::bringup_dhcp().await {
                Ok(())
            } else {
                // No implicit static fallback — surfacing the
                // timeout lets callers decide whether to retry
                // with `NetBringUp::Static{…}` or panic.
                Err(NetError::Dhcp(DhcpError::Timeout))
            }
        }
        NetBringUp::Static { ip, gateway, netmask } => {
            uni_net_stack::bringup_static(
                to_net_ipv4(ip),
                to_net_ipv4(gateway),
                to_net_ipv4(netmask),
            );
            Ok(())
        }
    }
}

#[cfg(not(target_os = "none"))]
async fn bringup(_cfg: NetBringUp) -> Result<(), NetError> {
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
fn to_net_ipv4(a: Ipv4Addr) -> uni_net_stack::types::Ipv4Addr {
    let [o0, o1, o2, o3] = a.0;
    uni_net_stack::types::Ipv4Addr::from(o0, o1, o2, o3)
}
