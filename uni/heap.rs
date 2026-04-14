// uni/heap.rs — Platform-agnostic raw allocator backend for uni::owned.
//
// Provides `alloc(size)` and `dealloc(ptr)` that resolve to:
//   - kernel::mm::{kmalloc, kfree} on unikernel
//   - libc malloc / free on native (via the OS allocator already linked
//     in for sockets / pthreads)
//
// This is the bottom layer of `uni::Box` and `uni::Buffer`. The
// `#[global_allocator]` itself lives in `kernel::mm::GLOBAL_ALLOCATOR`
// so that crates linking against `kernel` directly (e.g. `boot/limine`)
// also pick up the allocator without having to add `uni` to their deps.
//
// Both `alloc` and `dealloc` are safe to call: returning null on OOM is
// well-defined, and `dealloc(ptr)` is sound because the only callers are
// the owning smart-pointer types in `uni::owned`, which uphold the
// "exactly one free per alloc" invariant via Drop.

#[cfg(platform_unikernel)]
#[inline]
pub fn alloc(size: usize) -> *mut u8 {
    kernel::mm::kmalloc(size)
}

#[cfg(platform_unikernel)]
#[inline]
pub fn dealloc(ptr: *mut u8) {
    kernel::mm::kfree(ptr);
}

// (`#[global_allocator]` lives in `kernel::mm` — see kernel/mm.rs.)

#[cfg(platform_native)]
unsafe extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
}

#[cfg(platform_native)]
#[inline]
pub fn alloc(size: usize) -> *mut u8 {
    // SAFETY: malloc with a non-negative size is well-defined.
    unsafe { malloc(size) }
}

#[cfg(platform_native)]
#[inline]
pub fn dealloc(ptr: *mut u8) {
    // SAFETY: free is well-defined for null and for pointers previously
    // returned by malloc; uni::owned upholds the latter invariant.
    unsafe { free(ptr) }
}
