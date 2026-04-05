// kernel/x86_64/x86_init.rs — x86_64 arch initialization (crate root)
//
// Provides GDT and IDT setup for x86_64 bare-metal boot.
// On aarch64 this crate is empty (modules are cfg-gated).

#![no_std]
#![allow(static_mut_refs)]
#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
pub mod gdt;

#[cfg(target_arch = "x86_64")]
pub mod idt;
