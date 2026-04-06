// kernel/lib.rs — Crate root for the unified kernel library.
//
// Combines types, serial, memory management, FDT, MMU, exceptions,
// and x86_64 arch init into a single `kernel` crate with modules.

#![no_std]
#![allow(static_mut_refs)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]  // FDT/MMU code is aarch64-only, x86_64 code is x86-only

pub mod types;
pub mod fdt;
pub mod mmu;
pub mod serial;
pub mod mm;
pub mod exceptions;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
