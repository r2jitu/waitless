// bazel/rules/native_main.rs — Root crate for native rust_binary
//
// Provides #[panic_handler], rust_eh_personality, and a libc-backed
// #[global_allocator] so the no_std `//uni` crate can link against
// crates that need heap allocation (p256, hmac, etc. — pulled in by
// the hand-rolled TLS 1.3 stack when `//uni:uni` uses tls_server
// on native). The actual main() comes from uni::native, and
// uni_main() comes from the app library (linked via deps).

#![no_std]
#![no_main]

extern crate uni;

// Force the app library to be linked (it provides uni_main).
// The app crate name is set by unikernel_binary() via --extern.
extern crate app;

// ── Libc-backed global allocator ────────────────────────────────────
//
// Thin `GlobalAlloc` shim over `malloc` / `free` / `posix_memalign`.
// Enough to satisfy `#![no_std]` + `extern crate alloc` on POSIX
// hosts. Not production-grade (no stats, no cgroup limits, no
// hardening) but this binary only exists to run bench comparisons
// against the unikernel, so trading rigor for a 30-line allocator
// is the right call here.

use core::alloc::{GlobalAlloc, Layout};

struct LibcAllocator;

unsafe extern "C" {
    fn malloc(size: usize) -> *mut core::ffi::c_void;
    fn free(ptr: *mut core::ffi::c_void);
    fn posix_memalign(
        memptr: *mut *mut core::ffi::c_void,
        alignment: usize,
        size: usize,
    ) -> i32;
}

unsafe impl GlobalAlloc for LibcAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        if align <= core::mem::size_of::<usize>() {
            // `malloc` already guarantees alignment up to `max_align_t`
            // (usually 16 on 64-bit), which covers `align <= 8` and
            // `align == 16`. Use it directly for the common case.
            unsafe { malloc(size) as *mut u8 }
        } else {
            // Over-aligned allocations (`Layout::new::<AlignedBlob>()`
            // where AlignedBlob is e.g. 64-byte-aligned) need
            // `posix_memalign`. `alignment` must be a power of two
            // and a multiple of `sizeof(void*)`.
            let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
            let rc = unsafe { posix_memalign(&mut ptr, align, size) };
            if rc == 0 { ptr as *mut u8 } else { core::ptr::null_mut() }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { free(ptr as *mut core::ffi::c_void) }
    }
}

#[global_allocator]
static GLOBAL: LibcAllocator = LibcAllocator;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    uni::log(b"PANIC\n");
    loop { core::hint::spin_loop(); }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
