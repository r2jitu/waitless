// uni/heap.rs — Platform-agnostic raw allocator backend + global allocator.
//
// Provides `alloc(size)` and `dealloc(ptr)` that resolve to:
//   - kernel::mm::{kmalloc, kfree} on unikernel
//   - libc malloc / free on native (via the OS allocator already linked
//     in for sockets / pthreads)
//
// This is the bottom layer of `uni::Box` and `uni::Buffer`. It also
// installs a `#[global_allocator]` on the unikernel platform so crates
// that use `alloc::{vec::Vec, string::String, boxed::Box}` internally
// (e.g. RustCrypto's sha2, hmac, x25519-dalek for TLS 1.3) link
// correctly. The global allocator simply forwards to the raw backend.
//
// On the native platform the system allocator is already installed
// via libstd's default; we don't override it.
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

// ── Global allocator for no_std + alloc crates ───────────────────────────────
//
// Installed only on the unikernel platform. Forwards every allocation
// to `kernel::mm::kmalloc` / `kfree` — the same heap that `uni::Box`
// uses — so every crate depending on `uni` automatically gets a
// working `alloc::*` without any explicit `#[global_allocator]`.
//
// `GlobalAlloc` requires alignment support, which the raw backend
// doesn't currently expose. `kmalloc` returns 16-byte-aligned pointers,
// which is enough for every type we currently allocate (the largest
// required alignment in the RustCrypto TLS deps is 16 for AES blocks).
// If a future crate needs a larger alignment the allocator will hand
// out a pointer that panics on the debug assertion below, which is
// preferable to silent UB.

#[cfg(platform_unikernel)]
pub struct UniAllocator;

#[cfg(platform_unikernel)]
unsafe impl core::alloc::GlobalAlloc for UniAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let p = kernel::mm::kmalloc(layout.size());
        // kmalloc returns 16-byte-aligned pointers; anything larger
        // would need a custom aligned allocator.
        debug_assert!(
            layout.align() <= 16,
            "uni::heap::UniAllocator can't honour align > 16"
        );
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        kernel::mm::kfree(ptr);
    }
}

#[cfg(platform_unikernel)]
#[global_allocator]
pub static GLOBAL_ALLOCATOR: UniAllocator = UniAllocator;

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
