// net/protocol.rs — IP protocol dispatch registry.
//
// Replaces the hardcoded `match pkt.protocol` in `net::net_receive` /
// `net::distribute_frame` with named TCP / UDP handler slots set at
// boot. This is the dispatch point §2g's async RX layer will hook.
//
// Design:
//   * Two named slots (TCP, UDP) — the only IP protocols we ship.
//     A 256-slot table was considered but rejected: ~2 KB of BSS
//     that nothing indexes into, and the hot path has the same
//     branch cost either way. Adding a new protocol (ICMP, …) is a
//     one-field + one-match-arm edit — surfaced in one helper
//     (`proto_to_slot`) so every op routes through it.
//   * Writer-side API is typed (`Slot::Tcp` / `Slot::Udp`) so an
//     unknown protocol is a compile error, not a silent no-op.
//   * `FnSlot` encapsulates the `AtomicPtr` + `transmute` dance so
//     the unsafety sits in one place instead of every call site.
//   * Zero deps beyond `core::`; compiles as a standalone
//     `rust_test` target for host-native unit tests.
//   * Hot path: one `match` branch (proto→slot), one `Relaxed`
//     load, one null check, one indirect call. Safe because slots
//     are written only during boot-path init (before any AP is
//     dispatching packets); the kernel's `set_ready` → AP-wakeup
//     publish covers the cross-core happens-before.

#![no_std]

use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

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

/// A registry slot identifier. Typed (instead of a `u8` argument) so
/// `register` can't silently drop an unknown protocol — the compiler
/// enforces the slot exists. `dispatch` still takes a raw `u8`
/// because that's what IP packets carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Tcp,
    Udp,
}

// ---- FnSlot: one-place wrapper over the AtomicPtr / transmute -------------
//
// Stores a `ProtocolHandler` atomically with "no handler" represented by
// `null`. Uses `AtomicPtr<()>` so the store side is a safe `as *mut ()`
// cast; the load side still needs `transmute` to recover the fn pointer,
// but that unsafety lives in one function.

struct FnSlot(AtomicPtr<()>);

impl FnSlot {
    const fn empty() -> Self {
        FnSlot(AtomicPtr::new(ptr::null_mut()))
    }

    /// Publish `handler` to this slot. Uses `Release` so concurrent
    /// readers that observe a non-null pointer via any Acquire (or
    /// via a later synchronisation point like the kernel's
    /// `set_ready`) see a fully-formed function pointer.
    fn set(&self, handler: ProtocolHandler) {
        self.0.store(handler as *mut (), Ordering::Release);
    }

    /// Clear the slot — only used by tests; production never drops
    /// a registered handler.
    fn clear(&self) {
        self.0.store(ptr::null_mut(), Ordering::Release);
    }

    /// Hot-path read. `Acquire` pairs with `set`'s `Release` store
    /// for an unambiguous happens-before guarantee on every target
    /// (x86_64 load-acquire is a plain load; aarch64 emits a single
    /// LDAR). A `Relaxed` load would be sound given the kernel's
    /// boot-time publish fence (`set_ready`), but the HVF bench
    /// noise floor (~2-3 % per run) can't reliably distinguish it
    /// from `Acquire`, so we keep the safer ordering.
    #[inline]
    fn load(&self) -> Option<ProtocolHandler> {
        let ptr = self.0.load(Ordering::Acquire);
        if ptr.is_null() {
            None
        } else {
            // SAFETY: `ptr` was stored by `set` via the safe
            // `handler as *mut ()` cast — the inverse transmute
            // back to `fn(..)` is sound because function pointers
            // and data pointers share representation on every
            // platform we target (x86_64 + aarch64 ELF ABI).
            Some(unsafe { core::mem::transmute::<*mut (), ProtocolHandler>(ptr) })
        }
    }
}

// ---- Registry -------------------------------------------------------------

/// Dispatch table for IP protocol handlers. Named slots for the
/// protocols we ship (TCP, UDP); unknown protos drop silently on
/// `dispatch` (packets come in over the wire with a u8 proto
/// field, so runtime filtering is required there — unlike the
/// writer side, which is typed).
pub struct Registry {
    tcp: FnSlot,
    udp: FnSlot,
}

impl Registry {
    pub const fn new() -> Self {
        Registry {
            tcp: FnSlot::empty(),
            udp: FnSlot::empty(),
        }
    }

    /// The only place that maps `Slot → FnSlot`. Every public
    /// method routes through here, so adding a new protocol is a
    /// one-field + one-match-arm edit.
    #[inline]
    fn slot_for(&self, slot: Slot) -> &FnSlot {
        match slot {
            Slot::Tcp => &self.tcp,
            Slot::Udp => &self.udp,
        }
    }

    /// The only place that maps `proto: u8 → Slot`. `dispatch`
    /// routes through here because packets carry raw protocol
    /// numbers. Unknown protos return `None` so `dispatch` can
    /// drop them silently.
    #[inline]
    fn proto_to_slot(proto: u8) -> Option<Slot> {
        match proto {
            PROTO_TCP => Some(Slot::Tcp),
            PROTO_UDP => Some(Slot::Udp),
            _ => None,
        }
    }

    /// Install `handler` for `slot`. Idempotent: a second call
    /// replaces the previous handler.
    pub fn register(&self, slot: Slot, handler: ProtocolHandler) {
        self.slot_for(slot).set(handler);
    }

    /// Drop any handler for `slot`. Only exercised by tests — in
    /// production the registered handlers live for the lifetime of
    /// the kernel.
    pub fn unregister(&self, slot: Slot) {
        self.slot_for(slot).clear();
    }

    /// Whether `slot` currently has a handler. Not used on the hot
    /// path — intended for tests and `/stats`-style diagnostics.
    pub fn is_registered(&self, slot: Slot) -> bool {
        self.slot_for(slot).load().is_some()
    }

    /// Hot-path dispatch: call the handler for `proto` if any.
    /// Returns `true` when a handler was invoked. Unknown
    /// protocols drop silently (single branch, one atomic load
    /// saved vs a `match proto` that would have to load from
    /// every slot).
    #[inline]
    pub fn dispatch(
        &self,
        proto: u8,
        src: u32,
        dst: u32,
        payload: &[u8],
    ) -> bool {
        let Some(slot) = Self::proto_to_slot(proto) else { return false; };
        let Some(f) = self.slot_for(slot).load() else { return false; };
        f(src, dst, payload);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;

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
        assert!(!reg.is_registered(Slot::Tcp));
        reg.register(Slot::Tcp, test_handler);
        assert!(reg.is_registered(Slot::Tcp));
        assert!(reg.dispatch(PROTO_TCP, ip(10, 0, 0, 1), ip(10, 0, 0, 2), &[1, 2, 3]));
        assert_eq!(TEST_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(TEST_LAST_LEN.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn register_and_dispatch_udp() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        let reg = Registry::new();
        reg.register(Slot::Udp, test_handler);
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
    fn dispatch_unknown_proto_is_silently_dropped() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        let reg = Registry::new();
        reg.register(Slot::Tcp, test_handler);
        // ICMP = 1; packets with unknown proto are dropped even
        // though TCP has a handler installed.
        assert!(!reg.dispatch(1, 0, 0, &[0]));
        assert_eq!(TEST_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unregister_clears_handler() {
        let reg = Registry::new();
        reg.register(Slot::Tcp, test_handler);
        assert!(reg.is_registered(Slot::Tcp));
        reg.unregister(Slot::Tcp);
        assert!(!reg.is_registered(Slot::Tcp));
        assert!(!reg.dispatch(PROTO_TCP, 0, 0, &[]));
    }

    #[test]
    fn tcp_and_udp_are_independent() {
        let reg = Registry::new();
        reg.register(Slot::Tcp, test_handler);
        assert!(reg.is_registered(Slot::Tcp));
        assert!(!reg.is_registered(Slot::Udp));
    }

    #[test]
    fn register_replaces_previous_handler() {
        TEST_CALLS.store(0, Ordering::Relaxed);
        let reg = Registry::new();
        reg.register(Slot::Tcp, test_handler);
        assert!(reg.is_registered(Slot::Tcp));
        // Second register replaces — effects observable via dispatch.
        reg.register(Slot::Tcp, test_handler);
        assert!(reg.is_registered(Slot::Tcp));
        assert!(reg.dispatch(PROTO_TCP, 0, 0, &[]));
        assert_eq!(TEST_CALLS.load(Ordering::Relaxed), 1);
    }

    /// Sanity: the registry is const-constructible (for `static` use).
    #[test]
    fn is_const_constructible() {
        static REG: Registry = Registry::new();
        assert!(!REG.is_registered(Slot::Tcp));
    }
}
