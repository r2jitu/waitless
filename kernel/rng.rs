// kernel/rng.rs — Kernel random number generator.
//
// Provides a `getrandom` custom backend so that crates pulling in
// `rand_core::OsRng` (RustCrypto AEADs, x25519-dalek, p256,
// rustls-rustcrypto, ...) can fill buffers without an OS syscall.
//
// Construction:
//
// 1. **Seed** — gather entropy from CPU cycle/time counters by reading
//    them in a tight loop and mixing through SHA-256. This is a
//    classic "jitter entropy" source: the variability between
//    consecutive cycle reads, hash of cache state, branch predictor
//    state, and microarchitectural noise gives us a few bits of
//    entropy per read. We do 256 reads → 256 mixed inputs into
//    SHA-256 → 256-bit seed.
//
//    On x86_64 we ALSO try `RDRAND` (CPUID feature bit 30 of
//    leaf 1, ECX) and mix its output in if available. RDRAND is
//    present on every Intel CPU since Ivy Bridge (2012) and every
//    AMD CPU since Zen (2017), which matches our `x86_64-v3`
//    target baseline.
//
// 2. **Expansion** — the seed keys a ChaCha20 stream cipher whose
//    keystream we hand back to callers. This is the same pattern
//    Linux's `getrandom(2)` uses. ChaCha20 is in our build already
//    via the `chacha20` crate (transitive of `chacha20poly1305`).
//
// **NOT a CSPRNG yet for production use.** The jitter source has not
// been formally analysed for our targets, RDRAND alone shouldn't be
// trusted (intel-sa-00329), and we don't reseed at runtime. For dev
// and CI this is fine. Production reseeding + a properly audited
// entropy collector is tracked under "Deferred work" in ROADMAP.md.

#![allow(unsafe_op_in_unsafe_fn)] // SAFETY documented per call site

extern crate chacha20;
extern crate getrandom;
extern crate sha2;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use core::cell::UnsafeCell;
use sha2::{Digest, Sha256};

use crate::sync::Spinlock;

// ============================================================================
// Entropy collection
// ============================================================================

/// Read the platform cycle counter — TSC on x86_64, CNTVCT_EL0 on
/// aarch64. Both are 64-bit, monotonic-ish, and readable in user mode
/// (which doesn't matter for us since we run in EL1/ring0).
#[inline(always)]
fn read_cycle_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        // SAFETY: RDTSC is unprivileged on every x86_64 target we run
        // (CR4.TSD is cleared during BSP init) and has no effect
        // beyond writing EDX:EAX, which we claim via `out`.
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let v: u64;
        // SAFETY: CNTVCT_EL0 is the unprivileged virtual counter;
        // MRS from it is always permitted at EL1 and has no side
        // effects beyond writing the destination register.
        core::arch::asm!(
            "mrs {0}, cntvct_el0",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0u64
    }
}

/// Try one `RDRAND` read on x86_64. Returns `Some(value)` on success,
/// `None` if the instruction returned CF=0 (entropy not ready). RDRAND
/// can spuriously fail; callers must treat it as best-effort.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn try_rdrand() -> Option<u64> {
    let value: u64;
    let ok: u8;
    // SAFETY: RDRAND is unprivileged and has no memory or stack
    // effects; it writes the named output register and sets CF.
    // We don't use `preserves_flags` because SETC reads CF.
    unsafe {
        core::arch::asm!(
            "rdrand {0}",
            "setc {1}",
            out(reg) value,
            out(reg_byte) ok,
            options(nomem, nostack),
        );
    }
    if ok != 0 { Some(value) } else { None }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn try_rdrand() -> Option<u64> {
    None
}

/// Mix 256 cycle-counter reads + best-effort RDRAND samples through
/// SHA-256 to produce a 32-byte seed.
fn collect_seed() -> [u8; 32] {
    let mut h = Sha256::new();

    // Constant tag — domain separates this seed from any other use of
    // SHA-256 in the kernel.
    h.update(b"unikernel kernel rng seed v1\0");

    // 256 cycle-counter reads with tiny intervening work so the next
    // read sees different microarchitectural state.
    for i in 0..256u32 {
        let t = read_cycle_counter();
        h.update(t.to_le_bytes());
        h.update(i.to_le_bytes());
        // Best-effort RDRAND mix-in. Try a few times; if RDRAND is
        // missing or temporarily failing, skip.
        for _ in 0..2 {
            if let Some(r) = try_rdrand() {
                h.update(r.to_le_bytes());
                break;
            }
        }
        // Small varying spin to perturb the next cycle counter read.
        for _ in 0..((i & 7) + 1) {
            core::hint::spin_loop();
        }
    }

    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

// ============================================================================
// ChaCha20 keystream RNG
// ============================================================================

/// The kernel's RNG state. Lazily seeded on first `fill_bytes` call.
///
/// `Spinlock` because callers can come from any core and getrandom is
/// fundamentally a global resource. The lock is held briefly: one
/// `apply_keystream` call into a small buffer.
struct RngCell(UnsafeCell<Option<ChaCha20>>);
unsafe impl Sync for RngCell {}

static RNG: RngCell = RngCell(UnsafeCell::new(None));
static RNG_LOCK: Spinlock<()> = Spinlock::new(());

/// Fill `dest` with random bytes. Lazily seeds the RNG on first call.
pub fn fill_bytes(dest: &mut [u8]) {
    let _g = RNG_LOCK.lock();
    // SAFETY: RNG_LOCK serialises all accesses to RNG.
    let slot = unsafe { &mut *RNG.0.get() };
    if slot.is_none() {
        let seed = collect_seed();
        let key = chacha20::Key::from(seed);
        // Fixed all-zero IV — the cipher key itself carries the
        // freshness, and we never re-key.
        let iv = chacha20::Nonce::from([0u8; 12]);
        *slot = Some(ChaCha20::new(&key, &iv));
    }
    let cipher = slot.as_mut().expect("seeded above");
    // Generate keystream by encrypting a zero buffer of `dest.len()`.
    for b in dest.iter_mut() {
        *b = 0;
    }
    cipher.apply_keystream(dest);
}

// ============================================================================
// getrandom custom backend registration
// ============================================================================
//
// `getrandom 0.2`'s `register_custom_getrandom!` macro creates an
// `extern "Rust"` symbol named `__getrandom_custom` that the crate's
// runtime dispatch calls. The macro requires the function to take
// `&mut [u8]` and return `Result<(), getrandom::Error>`.
//
// Because the macro emits a symbol with a fixed name, the kernel
// crate is the only place that can register it (otherwise we'd get
// duplicate-symbol link errors). Every unikernel binary depends on
// `//kernel`, so this registration is always linked in.

fn getrandom_callback(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    fill_bytes(buf);
    Ok(())
}

getrandom::register_custom_getrandom!(getrandom_callback);
