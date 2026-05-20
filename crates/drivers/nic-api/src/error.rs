// drivers/nic-api/src/error.rs — Driver-side errors only.
//
// `NicError` is referenced by `NicOps` fn-pointer signatures, so it
// has to live in the trait crate. The application-level error types
// (`NetError`, `DhcpError`) used to live here too but moved to
// `crates/uni/net/src/error.rs` — they're facade-level concerns, not
// part of the driver ABI, and shouldn't be dragged into the build of
// every NIC driver crate.
//
// Design rules:
//   1. Errors fit in ≤ 2 pointers (16 bytes on 64-bit). Size assert
//      at the bottom enforces it.
//   2. `Copy + Debug + PartialEq` so callers can pattern-match and
//      tests can assert specific values.
//
// Self-contained (only `core::`) so this file compiles as a
// standalone `rust_test` for host-native unit tests.

#![allow(dead_code)] // Some variants are reserved for future use.

use core::fmt;

/// Driver-level failures surfaced from a specific NIC driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicError {
    /// Driver's `init` / queue-setup path failed (vring allocation,
    /// device negotiation, firmware response, etc.).
    InitFailed,
    /// TX ring full — caller should retry later.
    TxQueueFull,
    /// Descriptor ring invariant violation (wrap mismatch, bad
    /// cursor). Indicates either a driver or device bug.
    RingCorrupt,
    /// Device reported a hardware-level fault (e.g., link down after
    /// negotiating up).
    HwFault,
}

impl fmt::Display for NicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NicError::InitFailed => f.write_str("nic init failed"),
            NicError::TxQueueFull => f.write_str("nic tx queue full"),
            NicError::RingCorrupt => f.write_str("nic ring corrupt"),
            NicError::HwFault => f.write_str("nic hardware fault"),
        }
    }
}

// ---- Size invariant --------------------------------------------------------

const _: () = assert!(core::mem::size_of::<NicError>() <= 2 * core::mem::size_of::<usize>());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_under_two_pointers() {
        assert!(core::mem::size_of::<NicError>() <= 2 * core::mem::size_of::<usize>());
    }

    #[test]
    fn nic_error_variants_are_distinct() {
        assert_ne!(NicError::InitFailed, NicError::HwFault);
        assert_ne!(NicError::TxQueueFull, NicError::RingCorrupt);
    }

    #[test]
    fn display_renders() {
        // No alloc dep in nic_api; use core's write! to a fixed buffer.
        use core::fmt::Write as _;
        let mut buf = [0u8; 64];
        let n = {
            let mut s = Slice {
                buf: &mut buf,
                n: 0,
            };
            let _ = write!(s, "{}", NicError::HwFault);
            s.n
        };
        assert_eq!(&buf[..n], b"nic hardware fault");
    }

    struct Slice<'a> {
        buf: &'a mut [u8],
        n: usize,
    }
    impl core::fmt::Write for Slice<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let cap = self.buf.len() - self.n;
            let take = core::cmp::min(bytes.len(), cap);
            self.buf[self.n..self.n + take].copy_from_slice(&bytes[..take]);
            self.n += take;
            Ok(())
        }
    }
}
