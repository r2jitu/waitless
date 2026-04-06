// kernel/lib.rs — Unified kernel library crate.
//
// Platform-independent modules at the top level, arch-specific
// modules in x86_64/ and aarch64/ subdirectories.

#![no_std]
#![allow(static_mut_refs)]

pub mod types;
pub mod serial;
pub mod mm;
pub mod time;
pub mod deque;
pub mod spsc;
pub mod timer;
pub mod percpu;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

