// waitless/net/src/error.rs — Facade-level net errors.
//
// `NetError` (the top-level error for `Net::enable` / interface
// bring-up) and `DhcpError` (DHCP-client failure modes) live here in
// the facade crate, NOT in `nic_api`. nic_api is the driver-ABI leaf
// crate — DHCP-protocol error variants have no business living in
// the trait crate every NIC driver depends on. NicError stays in
// nic_api (it appears in `Nic` method signatures).
//
// Design rules unchanged from the previous co-located version:
//   1. Every error fits in ≤ 2 pointers (16 bytes on 64-bit). Keeps
//      `Result<T, E>` compact at call sites. Size asserts below.
//   2. Errors are `Copy + Debug + PartialEq` so callers can pattern-
//      match on them and tests can assert specific values.
//   3. Conversions chain upward: driver/DHCP failures bubble into
//      `NetError`. Never downward.
//
// Self-contained outside `nic_api::NicError` — only `core::` plus
// the one upstream import — so this file also compiles as a
// standalone `rust_test` for host-native unit tests.
//
// Some variants are reserved for future use.

use core::fmt;
use nic_api::NicError;

// ---- DhcpError -------------------------------------------------------------

/// Failures from DHCP v4 client bring-up (`NetBringUp::Dhcp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpError {
    /// DISCOVER / REQUEST timed out without a server reply.
    Timeout,
    /// Server replied but the message was malformed.
    BadReply,
    /// OFFER received but contained no usable IP.
    NoOffer,
    /// Server sent NAK in response to REQUEST.
    Nak,
}

impl fmt::Display for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpError::Timeout => f.write_str("dhcp timeout"),
            DhcpError::BadReply => f.write_str("dhcp bad reply"),
            DhcpError::NoOffer => f.write_str("dhcp no offer"),
            DhcpError::Nak => f.write_str("dhcp server nak"),
        }
    }
}

// ---- NetError --------------------------------------------------------------

/// Top-level error for the network stack's control/init paths
/// (driver probe, interface bring-up, DHCP). Datapath errors (per-
/// packet TX/RX) use `NicError` directly and do not bubble through
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// No ethernet driver is linked into the binary. Add a driver
    /// crate dep (e.g. `//crates/drivers/virtio-net`, `//crates/drivers/gve`).
    NoDriver,
    /// At least one driver was linked but none found a NIC to bind.
    NoNic,
    /// A probed driver returned a hard failure.
    Nic(NicError),
    /// DHCP bring-up failed.
    Dhcp(DhcpError),
    /// `Net::enable` was called more than once per boot.
    AlreadyEnabled,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::NoDriver => f.write_str("no ethernet driver linked"),
            NetError::NoNic => f.write_str("no NIC matched any driver"),
            NetError::Nic(e) => write!(f, "nic: {}", e),
            NetError::Dhcp(e) => write!(f, "dhcp: {}", e),
            NetError::AlreadyEnabled => f.write_str("Net::enable already called"),
        }
    }
}

impl From<NicError> for NetError {
    fn from(e: NicError) -> Self {
        NetError::Nic(e)
    }
}

impl From<DhcpError> for NetError {
    fn from(e: DhcpError) -> Self {
        NetError::Dhcp(e)
    }
}

// ---- Size invariants -------------------------------------------------------

const MAX_ERROR_BYTES: usize = 2 * core::mem::size_of::<usize>();

const _: () = assert!(core::mem::size_of::<DhcpError>() <= MAX_ERROR_BYTES);
const _: () = assert!(core::mem::size_of::<NetError>() <= MAX_ERROR_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_under_two_pointers() {
        let max = 2 * core::mem::size_of::<usize>();
        assert!(core::mem::size_of::<DhcpError>() <= max);
        assert!(core::mem::size_of::<NetError>() <= max);
    }

    #[test]
    fn from_nic_error_wraps() {
        let n: NicError = NicError::InitFailed;
        let e: NetError = n.into();
        assert_eq!(e, NetError::Nic(NicError::InitFailed));
    }

    #[test]
    fn from_dhcp_error_wraps() {
        let d: DhcpError = DhcpError::Timeout;
        let e: NetError = d.into();
        assert_eq!(e, NetError::Dhcp(DhcpError::Timeout));
    }

    #[test]
    fn question_mark_lifts_inner_to_outer() {
        fn inner() -> Result<(), NicError> {
            Err(NicError::HwFault)
        }
        fn outer() -> Result<(), NetError> {
            inner()?;
            Ok(())
        }
        assert_eq!(outer(), Err(NetError::Nic(NicError::HwFault)));
    }

    #[test]
    fn question_mark_lifts_dhcp_to_net() {
        fn inner() -> Result<(), DhcpError> {
            Err(DhcpError::NoOffer)
        }
        fn outer() -> Result<(), NetError> {
            inner()?;
            Ok(())
        }
        assert_eq!(outer(), Err(NetError::Dhcp(DhcpError::NoOffer)));
    }

    #[test]
    fn display_renders_chain() {
        use core::fmt::Write as _;
        let mut s = ::std::string::String::new();
        let e: NetError = DhcpError::Timeout.into();
        let _ = write!(s, "{}", e);
        assert_eq!(s.as_str(), "dhcp: dhcp timeout");
    }

    #[test]
    fn net_error_variants_are_distinct() {
        assert_ne!(NetError::NoDriver, NetError::NoNic);
        assert_ne!(NetError::NoDriver, NetError::AlreadyEnabled);
        assert_ne!(
            NetError::Nic(NicError::InitFailed),
            NetError::Nic(NicError::HwFault),
        );
    }
}
