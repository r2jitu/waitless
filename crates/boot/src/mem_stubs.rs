// boot/mem_stubs.rs — Compiler-required memory intrinsics (memcpy/memset/memmove/memcmp).
// Not a libc; just the three byte-loop helpers LLVM emits calls to on bare metal.

#![no_std]

// No `#[panic_handler]` here: this crate is a plain rlib linked into
// the unikernel binary, whose sole handler lives in `entry`.

/// Copy `n` bytes from `src` to `dest`.
///
/// # Safety
///
/// `dest` and `src` must each point to at least `n` valid bytes, with
/// `dest` writable. The two regions must not overlap — use `memmove`
/// when they might.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
        dest
    }
}

/// Fill `n` bytes at `dest` with the low byte of `val`.
///
/// # Safety
///
/// `dest` must point to at least `n` bytes that are valid and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, val: i32, n: usize) -> *mut u8 {
    unsafe {
        let v = val as u8;
        let mut i = 0;
        while i < n {
            *dest.add(i) = v;
            i += 1;
        }
        dest
    }
}

/// Copy `n` bytes from `src` to `dest`, tolerating overlapping regions.
///
/// # Safety
///
/// `dest` and `src` must each point to at least `n` valid bytes, with
/// `dest` writable. Unlike `memcpy`, the regions are allowed to overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
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
}

/// Compare the first `n` bytes of `s1` and `s2`.
///
/// # Safety
///
/// Both `s1` and `s2` must point to at least `n` valid bytes to read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe {
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
}
