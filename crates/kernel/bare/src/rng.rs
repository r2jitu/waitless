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
// 3. **Reseed** — every `RESEED_INTERVAL_BYTES` of output, fold fresh
//    jitter + hardware entropy back into the seed
//    (`new = SHA256(tag || old_seed || counter || fresh)`). Because the
//    old seed is an input, a reseed can only *add* entropy, so it's
//    safe even if the fresh sample is weak; it gives the SP 800-90A
//    reseed properties (bounded output per seed, ongoing entropy
//    injection, self-healing after a state compromise).
//
// **Hardware entropy sources** (best-effort, gated, folded — never
// trusted alone, per intel-sa-00329): RDSEED + RDRAND on x86_64,
// `RNDR` (FEAT_RNG) on aarch64 where implemented. Apple M-series lacks
// FEAT_RNG, so the HVF dev path runs jitter-only as before.
//
// **Still deferred (docs/roadmap.md "Deferred & parked"):** a formally
// analysed min-entropy estimate for the jitter source on each target,
// and a virtio-rng / aarch64-RNDRRS health-checked collector. The
// construction here (folded reseed + multi-source HW mix + SHA-256
// Hash_DRBG) is a sound production CSPRNG; what's missing is the
// *measurement* that would let us state a guaranteed min-entropy
// floor rather than a believed-sufficient one.

use core::cell::UnsafeCell;
use sha2::{Digest, Sha256};

use sync::Spinlock;

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

/// Try one `RDSEED` read on x86_64 — the *true-entropy* source feeding
/// RDRAND's conditioner (RDRAND is a DRBG reseeded from RDSEED). Prefer
/// it for reseeds. CPUID leaf 7, EBX bit 18; absent on pre-Broadwell.
/// Best-effort: CF=0 means the entropy pool was momentarily drained.
#[cfg(target_arch = "x86_64")]
#[inline]
fn try_rdseed() -> Option<u64> {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 = unknown, 1 = supported, 2 = absent.
    static SUPPORTED: AtomicU8 = AtomicU8::new(0);
    let ok = match SUPPORTED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let has = cpuid_leaf7_ebx_bit(18);
            SUPPORTED.store(if has { 1 } else { 2 }, Ordering::Relaxed);
            has
        }
    };
    if !ok {
        return None;
    }
    let value: u64;
    let cf: u8;
    // SAFETY: RDSEED is unprivileged, no memory/stack effects; writes
    // the named register and sets CF (read via SETC).
    unsafe {
        core::arch::asm!(
            "rdseed {0}",
            "setc {1}",
            out(reg) value,
            out(reg_byte) cf,
            options(nomem, nostack),
        );
    }
    if cf != 0 { Some(value) } else { None }
}

/// Read `CPUID.(EAX=7,ECX=0):EBX` and test one bit. EBX is reserved by
/// LLVM, so save/restore it around the `cpuid`.
#[cfg(target_arch = "x86_64")]
#[inline]
fn cpuid_leaf7_ebx_bit(bit: u32) -> bool {
    let ebx: u32;
    // SAFETY: CPUID is unprivileged; clobbers EAX/EBX/ECX/EDX, all
    // claimed below.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "mov rbx, {tmp:r}",
            tmp = out(reg) _,
            ebx = out(reg) ebx,
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => _,
            out("edx") _,
            options(nomem, nostack),
        );
    }
    (ebx >> bit) & 1 != 0
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn try_rdrand() -> Option<u64> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn try_rdseed() -> Option<u64> {
    None
}

/// Whether the CPU implements FEAT_RNG (ARMv8.5 `RNDR`/`RNDRRS`).
/// Detected once from `ID_AA64ISAR0_EL1[63:60] != 0`. Apple M-series
/// (the HVF dev target) does NOT implement it — so this stays `false`
/// there and the jitter source carries the seed, exactly as before.
#[cfg(target_arch = "aarch64")]
fn rndr_supported() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    static SUPPORTED: AtomicU8 = AtomicU8::new(0); // 0 unknown, 1 yes, 2 no
    match SUPPORTED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let isar0: u64;
            // SAFETY: ID_AA64ISAR0_EL1 is an EL1-readable feature ID
            // register; we run at EL1. No side effects.
            unsafe {
                core::arch::asm!(
                    "mrs {0}, ID_AA64ISAR0_EL1",
                    out(reg) isar0,
                    options(nomem, nostack, preserves_flags),
                );
            }
            let has = (isar0 >> 60) & 0xf != 0;
            SUPPORTED.store(if has { 1 } else { 2 }, Ordering::Relaxed);
            has
        }
    }
}

/// Try one `RNDR` read on aarch64 (FEAT_RNG). `None` when unsupported
/// or the entropy source couldn't deliver (PSTATE.Z set). Gated on
/// [`rndr_supported`] — executing `RNDR` without FEAT_RNG is UNDEFINED.
#[cfg(target_arch = "aarch64")]
#[inline]
fn try_rndr() -> Option<u64> {
    if !rndr_supported() {
        return None;
    }
    let value: u64;
    let ok: u64;
    // SAFETY: gated on FEAT_RNG above. RNDR (S3_3_C2_C4_0) sets
    // PSTATE.NZCV; `cset ne` reads it (Z=0 ⇒ a number was returned).
    // The two instructions stay adjacent so nothing clobbers the
    // flags between; `preserves_flags` is therefore omitted.
    unsafe {
        core::arch::asm!(
            "mrs {v}, S3_3_C2_C4_0",
            "cset {o}, ne",
            v = out(reg) value,
            o = out(reg) ok,
            options(nomem, nostack),
        );
    }
    if ok != 0 { Some(value) } else { None }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn try_rndr() -> Option<u64> {
    None
}

/// Mix all available hardware entropy sources for this target into the
/// hasher: RDSEED + RDRAND on x86_64, RNDR on aarch64. Each is
/// best-effort and gated; a target with none (e.g. Apple Silicon) adds
/// nothing here and relies on the jitter source. Folding through
/// SHA-256 means a weak or absent source can never *reduce* the seed's
/// entropy — only add to it.
fn mix_hw_entropy(h: &mut Sha256) {
    // RDSEED first (true entropy); try twice — it drains under load.
    for _ in 0..2 {
        if let Some(r) = try_rdseed() {
            h.update(r.to_le_bytes());
            break;
        }
    }
    for _ in 0..2 {
        if let Some(r) = try_rdrand() {
            h.update(r.to_le_bytes());
            break;
        }
    }
    if let Some(r) = try_rndr() {
        h.update(r.to_le_bytes());
    }
}

/// Collect `rounds` jitter-entropy reads (cycle-counter variance under
/// tiny intervening work) plus the hardware sources into the hasher.
/// Shared by initial seeding (many rounds) and reseed (fewer — it only
/// augments the existing seed, which is folded in alongside).
fn collect_jitter(h: &mut Sha256, rounds: u32) {
    for i in 0..rounds {
        let t = read_cycle_counter();
        h.update(t.to_le_bytes());
        h.update(i.to_le_bytes());
        mix_hw_entropy(h);
        // Small varying spin to perturb the next cycle counter read.
        for _ in 0..((i & 7) + 1) {
            core::hint::spin_loop();
        }
    }
}

/// Number of jitter rounds for the initial seed (cold bootstrap).
const SEED_ROUNDS: u32 = 256;
/// Number of jitter rounds per runtime reseed. Fewer than the cold
/// bootstrap because the reseed *augments* the existing seed (its
/// accumulated entropy is folded in), not bootstraps from nothing.
const RESEED_ROUNDS: u32 = 64;

/// Mix `SEED_ROUNDS` jitter reads + hardware entropy through SHA-256 to
/// produce a 32-byte cold-bootstrap seed.
fn collect_seed() -> [u8; 32] {
    let mut h = Sha256::new();
    // Constant tag — domain separates this seed from any other use of
    // SHA-256 in the kernel.
    h.update(b"unikernel kernel rng seed v1\0");
    collect_jitter(&mut h, SEED_ROUNDS);
    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

/// Domain-separation tag for a runtime reseed fold.
const RESEED_TAG: &[u8] = b"unikernel kernel rng reseed v1\0";

/// Fold fresh entropy into an existing seed:
/// `new = SHA256(RESEED_TAG || old_seed || counter || fresh_jitter+hw)`.
/// Because `old_seed` is an input, the result retains *all* of the
/// old seed's entropy regardless of how weak the fresh sample is — a
/// reseed can only strengthen the state, never weaken it. This is the
/// SP 800-90A reseed property the dev RNG lacked.
fn reseed_fold(old_seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RESEED_TAG);
    h.update(old_seed);
    h.update(counter.to_le_bytes());
    collect_jitter(&mut h, RESEED_ROUNDS);
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
    /// Output bytes produced under the current seed. When it crosses
    /// [`RESEED_INTERVAL_BYTES`] the seed is folded with fresh entropy
    /// (see `reseed_fold`) and this resets — bounding how much output
    /// any single seed ever generates and injecting ongoing entropy
    /// so a state compromise self-heals (SP 800-90A reseed).
    bytes_since_reseed: u64,
}

/// Output bytes between automatic reseeds. 1 MiB is far below the
/// Hash_DRBG security bound yet keeps the reseed cost (≈64 jitter
/// reads + a few SHA blocks, microseconds) negligible — a busy TLS
/// server emits a handful of KiB of key material per handshake, so a
/// reseed lands roughly every few-hundred handshakes.
const RESEED_INTERVAL_BYTES: u64 = 1 << 20;

struct RngCell(UnsafeCell<Option<ExpandState>>);
unsafe impl Sync for RngCell {}

static RNG: RngCell = RngCell(UnsafeCell::new(None));
static RNG_LOCK: Spinlock<()> = Spinlock::new(());

/// Domain separation tag for the expand step. Distinct from the seed-
/// collection tag in `collect_seed()` so a SHA-256 collision in one
/// would not produce a collision in the other.
const EXPAND_TAG: &[u8] = b"unikernel kernel rng expand v1\0";

/// Fill `dest` with random bytes. Lazily seeds the RNG on first call,
/// and folds in fresh entropy once a seed has produced
/// [`RESEED_INTERVAL_BYTES`].
pub fn fill_bytes(dest: &mut [u8]) {
    let _g = RNG_LOCK.lock();
    // SAFETY: RNG_LOCK serialises all accesses to RNG.
    let slot = unsafe { &mut *RNG.0.get() };
    let state = slot.get_or_insert_with(|| ExpandState {
        seed: collect_seed(),
        counter: 0,
        bytes_since_reseed: 0,
    });

    // Reseed BEFORE producing output when the current seed has emitted
    // its budget, so no more than RESEED_INTERVAL_BYTES (+ one request)
    // ever come from one seed. The fold keeps the old seed's entropy,
    // so this is always safe; the counter is carried in so output never
    // repeats even if the fresh sample is degenerate.
    if state.bytes_since_reseed >= RESEED_INTERVAL_BYTES {
        state.seed = reseed_fold(&state.seed, state.counter);
        state.bytes_since_reseed = 0;
    }

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
    state.bytes_since_reseed = state.bytes_since_reseed.saturating_add(dest.len() as u64);
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
