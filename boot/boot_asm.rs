// boot/boot_asm.rs — x86_64 multiboot/PVH boot assembly stub.
//
// This crate exists solely to host `boot.S` via `global_asm!`. boot.S
// contains 32-bit absolute relocations (R_X86_64_32) targeting the
// `.boot_bss` section, which can only be linked into a lower-half ELF
// (loaded at 0x100000 by QEMU/multiboot/PVH).
//
// The Limine higher-half ELF (`*.limine.elf`) does NOT depend on this
// crate. Limine enters at `limine_entry()` (defined in `boot/limine_entry.rs`)
// directly, bypassing the multiboot stub.

#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Unreachable in practice — this crate exports no Rust functions, just
    // assembly. The panic_handler is required by `rust_static_library`.
    loop {}
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("x86_64/boot.S"), options(att_syntax));
