#![no_std]
#![no_main]

use core::ffi::c_char;
use core::panic::PanicInfo;

extern "C" {
    fn serial_printf(fmt: *const c_char, ...);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        serial_printf(b"PANIC: Rust panicked!\n\0".as_ptr() as *const c_char);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn uni_main() -> i32 {
    unsafe {
        serial_printf(b"Hello from Rust!\n\0".as_ptr() as *const c_char);
    }
    0
}
