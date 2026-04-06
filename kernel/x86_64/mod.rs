// kernel/x86_64/mod.rs — x86_64 arch initialization module
//
// Provides GDT and IDT setup for x86_64 bare-metal boot.

pub mod gdt;
pub mod idt;
pub mod apic;
pub mod smp;
