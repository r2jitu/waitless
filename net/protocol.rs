// net/protocol.rs — IP protocol dispatch registry.
//
// Replaces the hardcoded `match pkt.protocol` in `net::net_receive` /
// `net::distribute_frame` with named TCP / UDP handler slots set at
// boot. This is the dispatch point §2g's async RX layer will hook.
//
// Design:
//   * Two named `AtomicUsize` slots (TCP, UDP) — the only IP
//     protocols we ship. A 256-slot table was considered but
//     rejected: ~2 KB of BSS that nothing currently indexes into,
//     and the hot path still does one branch + one atomic load,
//     which a 2-entry match does equally well (with smaller code
//     and better inlining). Adding a new protocol (ICMP, etc.) is
//     a one-slot + match-arm addition.
//   * Zero deps beyond `core::`; compiles as a standalone
//     `rust_test` target for host-native unit tests.
//   * Hot path: one `match` branch, one `Acquire` load, one
//     zero-check, one indirect call. Same branch cost as the
//     hardcoded TCP/UDP match it replaces, plus one indirect
//     call (the async layer needs a runtime-settable hook; a
//     direct call can't be re-pointed).
//
// `register` / `unregister` are safe (plain function-pointer store)
// and meant for boot-path init. `dispatch` is the per-packet hot
// path.

#![no_std]

use core::sync::atomic::{AtomicUsize, Ordering};

/// IPv4 protocol number for TCP (RFC 793).
pub const PROTO_TCP: u8 = 6;

/// IPv4 protocol number for UDP (RFC 768).
pub const PROTO_UDP: u8 = 17;

/// Signature every registered handler must have. IPs are raw `u32`
/// (network byte order, matching `net_types::Ipv4Addr::addr`) so this
/// crate stays free of the `net_types` dep. The umbrella crate
/// installs small wrappers that convert `u32` ↔ `Ipv4Addr` for the
/// existing `tcp_receive` / `udp_receive` entry points.
pub type ProtocolHandler = fn(src: u32, dst: u32, payload: &[u8]);

/// Dispatch table for IP protocol handlers. Named slots for the
/// protocols we ship (TCP, UDP); unknown protos drop silently.
pub struct Registry {
    /// Handler for `PROTO_TCP`, stored as `usize` so the struct is
    /// `const`-constructible. Zero = unregistered.
    tcp: AtomicUsize,
    /// Handler for `PROTO_UDP`. Zero = unregistered.
    udp: AtomicUsize,
}

impl Registry {
    pub const fn new() -> Self {
        Registry {
            tcp: AtomicUsize::new(0),
            udp: AtomicUsize::new(0),
        }
    }

    /// Install `handler` for `proto`. Returns the previous raw slot
    /// word (zero if it was empty). Unknown protocols return zero
    /// without storing — the registry only knows TCP / UDP.
    pub fn register(&self, proto: u8, handler: ProtocolHandler) -> usize {
        let slot = match proto {
            PROTO_TCP => &self.tcp,
            PROTO_UDP => &self.udp,
            _ => return 0,
        };
        slot.swap(handler as usize, Ordering::AcqRel)
    }

    /// Drop any handler for `proto`. Returns the previous raw word.
    pub fn unregister(&self, proto: u8) -> usize {
        let slot = match proto {
            PROTO_TCP => &self.tcp,
            PROTO_UDP => &self.udp,
            _ => return 0,
        };
        slot.swap(0, Ordering::AcqRel)
    }

    /// Hot-path dispatch: call the handler for `proto` if any.
    /// Returns `true` when a handler was invoked.
    #[inline]
    pub fn dispatch(
        &self,
        proto: u8,
        src: u32,
        dst: u32,
        payload: &[u8],
    ) -> bool {
        let word = match proto {
            PROTO_TCP => self.tcp.load(Ordering::Acquire),
            PROTO_UDP => self.udp.load(Ordering::Acquire),
            _ => return false,
        };
        if word == 0 {
            return false;
        }
        // SAFETY: `word` was stored by `register` as a transmuted
        // `ProtocolHandler` pointer and remains valid until
        // `unregister` stores zero. Function pointers are plain
        // machine words, so `transmute<usize, fn(..)>` is sound.
        let f: ProtocolHandler = unsafe { core::mem::transmute(word) };
        f(src, dst, payload);
        true
    }

    /// Whether `proto` currently has a handler. Not used on the hot
    /// path — intended for tests and `/stats`-style diagnostics.
    pub fn is_registered(&self, proto: u8) -> bool {
        let slot = match proto {
            PROTO_TCP => &self.tcp,
            PROTO_UDP => &self.udp,
            _ => return false,
        };
        slot.load(Ordering::Acquire) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_ne_bytes([a, b, c, d])
    }

    static TEST_CALLS: AtomicUsize = AtomicUsize::new(0);
    static TEST_LAST_LEN: AtomicUsize = AtomicUsize::new(0);

    fn test_handler(_src: u32, _dst: u32, payload: &[u8]) {
        TEST_CALLS.fetch_add(1, Ordering::Relaxed);
        TEST_LAST_LEN.store(payload.len(), Ordering::Relaxed);
    }

    #[test]
    fn register_and_dispatch_tcp() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        TEST_LAST_LEN.store(0, Ordering::Relaxed);
        let reg = Registry::new();
        assert!(!reg.is_registered(PROTO_TCP));
        assert_eq!(reg.register(PROTO_TCP, test_handler), 0);
        assert!(reg.is_registered(PROTO_TCP));
        assert!(reg.dispatch(PROTO_TCP, ip(10, 0, 0, 1), ip(10, 0, 0, 2), &[1, 2, 3]));
        assert_eq!(TEST_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(TEST_LAST_LEN.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn register_and_dispatch_udp() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        let reg = Registry::new();
        reg.register(PROTO_UDP, test_handler);
        assert!(reg.dispatch(PROTO_UDP, 0, 0, &[0; 5]));
        assert_eq!(TEST_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dispatch_unregistered_returns_false() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        let reg = Registry::new();
        assert!(!reg.dispatch(PROTO_TCP, 0, 0, &[]));
        assert_eq!(TEST_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unknown_proto_is_silently_dropped() {
        // ICMP = 1, not handled by this registry.
        let reg = Registry::new();
        assert_eq!(reg.register(1, test_handler), 0);
        assert!(!reg.is_registered(1));
        assert!(!reg.dispatch(1, 0, 0, &[0]));
    }

    #[test]
    fn unregister_clears_handler() {
        let reg = Registry::new();
        reg.register(PROTO_TCP, test_handler);
        assert!(reg.is_registered(PROTO_TCP));
        let prev = reg.unregister(PROTO_TCP);
        assert_ne!(prev, 0);
        assert!(!reg.is_registered(PROTO_TCP));
        assert!(!reg.dispatch(PROTO_TCP, 0, 0, &[]));
    }

    #[test]
    fn tcp_and_udp_are_independent() {
        let reg = Registry::new();
        reg.register(PROTO_TCP, test_handler);
        assert!(reg.is_registered(PROTO_TCP));
        assert!(!reg.is_registered(PROTO_UDP));
    }

    #[test]
    fn register_returns_previous_word() {
        let reg = Registry::new();
        assert_eq!(reg.register(PROTO_TCP, test_handler), 0);
        let prev = reg.register(PROTO_TCP, test_handler);
        assert_ne!(prev, 0, "second register should return previous handler word");
    }

    /// Sanity: the registry is const-constructible (for `static` use).
    #[test]
    fn is_const_constructible() {
        static REG: Registry = Registry::new();
        assert!(!REG.is_registered(PROTO_TCP));
    }
}
