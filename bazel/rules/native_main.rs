// bazel/rules/native_main.rs — Root crate for native rust_binary
//
// Provides #[panic_handler] and rust_eh_personality for no_std binaries.
// The actual main() comes from uni::native, and uni_main() comes from
// the app library (linked via deps).

#![no_std]
#![no_main]

extern crate uni;

// Force the app library to be linked (it provides uni_main).
// The app crate name is set by unikernel_binary() via --extern.
extern crate app;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    uni::log(b"PANIC\n");
    loop { core::hint::spin_loop(); }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
