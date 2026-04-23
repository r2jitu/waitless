// kernel/x86_64/mod.rs — x86_64 arch initialization module
//
// Provides GDT and IDT setup for x86_64 bare-metal boot.

pub mod acpi;
pub mod apic;
pub mod gdt;
pub mod idt;
pub mod smp;
