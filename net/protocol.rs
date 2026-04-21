// net/protocol.rs — IP protocol dispatch registry.
//
// Replaces the hardcoded `match pkt.protocol` in `net::net_receive` /
// `net::distribute_frame` with a runtime-populated table so TCP, UDP,
// and future protocols plug in without touching the umbrella.
//
// Design targets:
//   * O(1) dispatch cost — one acquire load + one branch + one
//     indirect call. Matches the branch cost of the replaced match.
//   * No heap allocation; 256-slot static array.
//   * `Copy`-free `fn` pointers stored as `AtomicUsize` so the table
//     is `const`-initialisable.
//
// `Registry::register` is safe (plain function-pointer store) and
// meant to be called once per protocol from a stack-init path.
// `dispatch` is the hot path, running once per incoming packet.
//
// Self-contained (only `core` + `net_types`) so the file compiles as
// a standalone `rust_test` for host-native unit tests.

#![no_std]

use core::sync::atomic::{AtomicUsize, Ordering};

/// Signature every registered handler must have. IPs are raw `u32`
/// (network byte order, matching `net_types::Ipv4Addr::addr`) so this
/// crate stays free of the `net_types` dep and compiles as a
/// standalone `rust_test`. The umbrella crate installs small wrappers
/// that convert `u32` ↔ `Ipv4Addr` for the existing `tcp_receive` /
/// `udp_receive` entry points.
pub type ProtocolHandler = fn(src: u32, dst: u32, payload: &[u8]);

/// 256-slot dispatch table indexed by IPv4 protocol number (or
/// IPv6 next-header — same mechanism, future work). A zero slot
/// means "no handler registered; drop the packet".
pub struct Registry {
    /// Function pointers stored as `usize` so the array can be
    /// `const`-constructed. Zero means "unregistered".
    slots: [AtomicUsize; 256],
}

impl Registry {
    pub const fn new() -> Self {
        Registry {
            slots: [const { AtomicUsize::new(0) }; 256],
        }
    }

    /// Register `handler` for `proto`. Returns the previous raw
    /// slot word (zero if it was empty). Intended to run once at
    /// stack-init time; replacing an existing handler is allowed
    /// but should only happen in tests.
    pub fn register(&self, proto: u8, handler: ProtocolHandler) -> usize {
        self.slots[proto as usize].swap(handler as usize, Ordering::AcqRel)
    }

    /// Drop the handler for `proto`. Returns the previous raw
    /// slot word. Packets for `proto` are subsequently ignored.
    pub fn unregister(&self, proto: u8) -> usize {
        self.slots[proto as usize].swap(0, Ordering::AcqRel)
    }

    /// Hot-path dispatch: call the handler for `proto` if any.
    /// Returns `true` when a handler was invoked, `false` when the
    /// slot was empty. The return value lets callers count
    /// unclaimed packets for diagnostics without a second lookup.
    #[inline]
    pub fn dispatch(
        &self,
        proto: u8,
        src: u32,
        dst: u32,
        payload: &[u8],
    ) -> bool {
        let h = self.slots[proto as usize].load(Ordering::Acquire);
        if h == 0 {
            return false;
        }
        // SAFETY: `h` was stored by `register` as a transmuted
        // `ProtocolHandler` pointer and is always valid until
        // `unregister` stores zero. Function pointers are plain
        // machine words, so `transmute<usize, fn(..)>` is sound.
        let f: ProtocolHandler = unsafe { core::mem::transmute(h) };
        f(src, dst, payload);
        true
    }

    /// Whether `proto` currently has a handler. Not used on the
    /// hot path — intended for tests and `/stats`-style
    /// diagnostics.
    pub fn is_registered(&self, proto: u8) -> bool {
        self.slots[proto as usize].load(Ordering::Acquire) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_ne_bytes([a, b, c, d])
    }

    /// Handlers shared across tests via Atomics. Each test resets the
    /// counters at the top.
    static TEST_CALLS: AtomicUsize = AtomicUsize::new(0);
    static TEST_LAST_LEN: AtomicUsize = AtomicUsize::new(0);

    fn test_handler(_src: u32, _dst: u32, payload: &[u8]) {
        TEST_CALLS.fetch_add(1, Ordering::Relaxed);
        TEST_LAST_LEN.store(payload.len(), Ordering::Relaxed);
    }

    #[test]
    fn register_and_dispatch() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        TEST_LAST_LEN.store(0, Ordering::Relaxed);

        let reg = Registry::new();
        assert!(!reg.is_registered(6));

        assert_eq!(reg.register(6, test_handler), 0);
        assert!(reg.is_registered(6));

        let src = ip(10, 0, 0, 1);
        let dst = ip(10, 0, 0, 2);
        let payload = [1u8, 2, 3, 4, 5];
        assert!(reg.dispatch(6, src, dst, &payload));
        assert_eq!(TEST_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(TEST_LAST_LEN.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn dispatch_unregistered_is_noop_and_returns_false() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        let reg = Registry::new();
        assert!(!reg.dispatch(99, 0, 0, &[]));
        assert_eq!(TEST_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unregister_removes_handler() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        let reg = Registry::new();
        reg.register(17, test_handler);
        assert!(reg.is_registered(17));

        let prev = reg.unregister(17);
        assert_ne!(prev, 0);
        assert!(!reg.is_registered(17));
        assert!(!reg.dispatch(17, 0, 0, &[0]));
    }

    #[test]
    fn protos_are_isolated() {
        let reg = Registry::new();
        reg.register(6, test_handler);
        assert!(reg.is_registered(6));
        assert!(!reg.is_registered(17));
        assert!(!reg.is_registered(0));
        assert!(!reg.is_registered(255));
    }

    #[test]
    fn register_returns_previous_word() {
        let reg = Registry::new();
        assert_eq!(reg.register(6, test_handler), 0);
        let prev = reg.register(6, test_handler);
        assert_ne!(prev, 0, "second register should return non-zero previous word");
    }
}
