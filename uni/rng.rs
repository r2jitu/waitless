// uni/rng.rs — platform-agnostic entropy source.
//
// Thin cfg-switch over the two backends:
//
//   * `target_os = "none"` → `kernel::rng::fill_bytes` (the kernel-
//     side PRNG, seeded at boot from `getrandom` via `chacha20`).
//   * else (unix host)     → `getentropy(2)` (POSIX; available on
//     macOS + Linux glibc/musl).
//
// Callers (TLS handshake seed, test harness, …) get one name
// regardless of runner. Previously `uni::http::fill_tls_seed` held
// the cfg-switch inline; extracting it lets `//apps/test_tls` drop
// its direct `kernel::rng` dep, which in turn lets test_tls run
// natively without pulling the kernel crate into the native
// dep-chain.

#[cfg(target_os = "none")]
pub fn fill_bytes(buf: &mut [u8]) {
    kernel::rng::fill_bytes(buf);
}

#[cfg(not(target_os = "none"))]
pub fn fill_bytes(buf: &mut [u8]) {
    // libc::getentropy fills up to 256 bytes from the host kernel's
    // entropy pool in one syscall. We declare it by hand rather
    // than depend on the `libc` crate because we only need this
    // symbol.
    unsafe extern "C" {
        fn getentropy(buf: *mut core::ffi::c_void, len: usize) -> i32;
    }
    // `getentropy` caps at 256 bytes per call; loop for larger asks.
    let mut offset = 0;
    while offset < buf.len() {
        let chunk = (buf.len() - offset).min(256);
        let rc = unsafe {
            getentropy(buf.as_mut_ptr().add(offset) as *mut _, chunk)
        };
        if rc != 0 {
            // `getentropy` effectively never fails in practice
            // (macOS + Linux both back it with a kernel RNG that's
            // always ready). Zero-fill the tail as a last resort
            // so callers see deterministic output they can detect
            // via their own sanity checks, rather than a panic
            // that would kill dev/bench processes.
            for b in &mut buf[offset..] {
                *b = 0;
            }
            return;
        }
        offset += chunk;
    }
}
