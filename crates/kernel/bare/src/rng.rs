// kernel/rng.rs — Kernel random number generator.
//
// Provides a `getrandom` custom backend so that crates pulling in
// `rand_core::OsRng` (RustCrypto AEADs, x25519-dalek, p256, ...) can
// fill buffers without an OS syscall.
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
// 2. **Expansion** — SHA-256 hash chain in counter mode. Each output
//    block is `SHA256("unikernel rng expand v1\0" || seed || ctr_le)`,
//    `ctr` advancing one per 32-byte block. This is the bulk
//    construction underlying NIST SP 800-90A's Hash_DRBG (without
//    the reseed counter logic, which we don't run long enough to
//    need). SHA-NI on x86_64-v3+ Intel CPUs and FEAT_SHA256 on
//    Apple Silicon / Graviton make this ~2-3 cycles/byte without
//    pulling in a separate stream cipher crate.
//
//    The previous ChaCha20-keystream construction was equivalent in
//    security but came from an outside crate (`chacha20` v0.9.x with
//    a known SIMD-correctness bug on `x86_64-unknown-none`, requiring
//    `--cfg=chacha20_force_soft` to dodge). Using `sha2` — already
//    a direct dep for jitter mixing + TLS / QUIC HKDF — drops a crate
//    from the kernel link line.
//
// **NOT a CSPRNG yet for production use.** The jitter source has not
// been formally analysed for our targets, RDRAND alone shouldn't be
// trusted (intel-sa-00329), and we don't reseed at runtime. For dev
// and CI this is fine. Production reseeding + a properly audited
// entropy collector is tracked under "Deferred work" in ROADMAP.md.

#![allow(unsafe_op_in_unsafe_fn)] // SAFETY documented per call site

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
// SHA-256 hash-chain expander
// ============================================================================

/// The kernel's RNG state. Lazily seeded on first `fill_bytes` call.
///
/// State is just `(seed, counter)` — each 32-byte output block is
/// `SHA256(TAG || seed || counter_le)`, counter advancing one per
/// block. `Spinlock` because callers can come from any core and
/// getrandom is fundamentally a global resource; the lock is held
/// briefly (one SHA-256 update + finalize per 32 bytes requested).
struct ExpandState {
    seed: [u8; 32],
    counter: u64,
}

struct RngCell(UnsafeCell<Option<ExpandState>>);
unsafe impl Sync for RngCell {}

static RNG: RngCell = RngCell(UnsafeCell::new(None));
static RNG_LOCK: Spinlock<()> = Spinlock::new(());

/// Domain separation tag for the expand step. Distinct from the seed-
/// collection tag in `collect_seed()` so a SHA-256 collision in one
/// would not produce a collision in the other.
const EXPAND_TAG: &[u8] = b"unikernel kernel rng expand v1\0";

/// Fill `dest` with random bytes. Lazily seeds the RNG on first call.
pub fn fill_bytes(dest: &mut [u8]) {
    let _g = RNG_LOCK.lock();
    // SAFETY: RNG_LOCK serialises all accesses to RNG.
    let slot = unsafe { &mut *RNG.0.get() };
    let state = slot.get_or_insert_with(|| ExpandState {
        seed: collect_seed(),
        counter: 0,
    });

    let mut offset = 0;
    while offset < dest.len() {
        let mut h = Sha256::new();
        h.update(EXPAND_TAG);
        h.update(state.seed);
        h.update(state.counter.to_le_bytes());
        let block = h.finalize();
        // Counter advances even on the partial-tail block so the
        // next call doesn't re-derive the same prefix.
        state.counter = state.counter.wrapping_add(1);

        let take = (dest.len() - offset).min(32);
        dest[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
    }
}

// ============================================================================
// kernel_core RNG link seam
// ============================================================================
//
// `kernel_core::rng::fill_bytes()` resolves, on the bare-metal target,
// to this `#[no_mangle]` symbol. `kernel_core` is the lower crate and
// cannot call up into `//crates/kernel/bare`, so it declares the `extern "Rust"`
// symbol and `//crates/kernel/bare` defines it here — mirroring `__kernel_bare_cpu_id`.
// This is what lets RNG-dependent host-buildable crates (`tcp`'s
// TCP initial-sequence-number selection) reach the real generator on
// `os:none` while resolving to a deterministic stream under host
// unit tests.

/// Link-seam definition for `kernel_core::rng::fill_bytes()`.
#[unsafe(no_mangle)]
pub extern "Rust" fn __kernel_bare_rng_fill(dest: &mut [u8]) {
    fill_bytes(dest);
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
// `//crates/kernel/bare`, so this registration is always linked in.

fn getrandom_callback(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    fill_bytes(buf);
    Ok(())
}

getrandom::register_custom_getrandom!(getrandom_callback);
