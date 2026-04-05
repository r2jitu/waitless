#![no_std]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}

// kernel/libc.rs — Compiler-required memory intrinsics
//
// The Rust compiler may emit calls to memcpy/memset/memmove/memcmp.
// On bare-metal targets, these are not provided by compiler_builtins
// (feature-gated), so we provide them here.
//
// Also provides the C++ ABI stubs (__cxa_pure_virtual, __cxa_atexit,
// __dso_handle) needed until all C++ is removed from the link.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, val: i32, n: usize) -> *mut u8 {
    let v = val as u8;
    let mut i = 0;
    while i < n {
        *dest.add(i) = v;
        i += 1;
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
    } else if (dest as usize) > (src as usize) {
        let mut i = n;
        while i > 0 {
            i -= 1;
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return (a as i32) - (b as i32);
        }
        i += 1;
    }
    0
}

// C++ ABI stubs — needed until all C++ code is removed from the link.
#[unsafe(no_mangle)]
pub extern "C" fn __cxa_pure_virtual() {
    loop { core::hint::spin_loop(); }
}

#[unsafe(no_mangle)]
pub extern "C" fn __cxa_atexit(_f: *const (), _arg: *const (), _dso: *const ()) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub static __dso_handle: usize = 0;
