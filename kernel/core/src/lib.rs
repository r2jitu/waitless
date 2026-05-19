// kernel_core — the host-buildable pure-logic core of the kernel.
//
// Lock-free data structures (deque, spsc, rx_inbox), per-core state
// (percpu), synchronisation primitives (sync), the in-memory
// diagnostic buffer (diag), and the plain boot-time data types —
// none of which touch hardware or arch-specific code. Split out of
// `//kernel` (which stays `os:none` for the MMU / APIC / boot code)
// so this logic is unit-testable on the host. `//kernel` re-exports
// every module here, so consumers using `uni_kernel::{percpu, sync,
// rx_inbox, ...}` are unaffected by the split.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod clock;
pub mod deque;
pub mod diag;
pub mod mmio;
pub mod once;
pub mod percpu;
pub mod rng;
pub mod rx_inbox;
pub mod spsc;
pub mod sync;
pub mod timer;
pub mod types;

/// Current CPU id.
///
/// On the bare-metal target this resolves, via a link seam, to
/// `//kernel`'s arch implementation (`__uni_kernel_cpu_id`);
/// `kernel_core` is the lower crate and cannot call up into the
/// arch modules, so it declares the symbol and `//kernel` defines
/// it. On a host build there is one logical CPU, so it is `0` —
/// which is what makes `net_tcp` (a `cpu_id` caller) host-testable.
///
/// Compile-time `cfg`, not a function pointer: the per-packet
/// callers (`tcp_receive`, the Tier-2 RX distributor) pay nothing
/// for the seam — production emits a single direct call, exactly as
/// before the split.
#[inline]
pub fn cpu_id() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe extern "Rust" {
            fn __uni_kernel_cpu_id() -> u32;
        }
        // SAFETY: `//kernel` defines this `#[no_mangle]` symbol, and
        // every `os:none` binary that links `kernel_core` also links
        // `//kernel` (it is the foundational crate).
        unsafe { __uni_kernel_cpu_id() }
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}
