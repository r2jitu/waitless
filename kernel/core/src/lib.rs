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

pub mod deque;
pub mod diag;
pub mod mmio;
pub mod once;
pub mod percpu;
pub mod rx_inbox;
pub mod spsc;
pub mod sync;
pub mod timer;
pub mod types;
