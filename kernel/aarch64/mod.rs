// kernel/aarch64/ — ARM64-specific kernel modules.
//
// FDT (device tree) parsing, MMU page table management,
// and GIC exception/interrupt handling.

pub mod fdt;
pub mod mmu;
pub mod exceptions;
