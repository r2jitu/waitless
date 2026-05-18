// bazel/rules/unikernel_main.rs — Root crate for unikernel rust_binary
//
// Thin wrapper that forces linking of the app and kernel entry crates.
// The actual entry point (_start) comes from boot.S assembly (included
// via global_asm! in entry.rs).

#![no_std]
#![no_main]

extern crate app;

// entry_rs provides the real panic handler (serial output + shutdown).
// This one exists only to satisfy the compiler for the binary crate root.
// --allow-multiple-definition at link time resolves the duplicate.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
