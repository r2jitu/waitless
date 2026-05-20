// crates/crypto/aes-gcm — hand-rolled AES-128-GCM with batched + stitched
// AES-CTR + GHASH.
//
// **Self-contained**: depends only on `aes` (for the AES-128
// round-key schedule and the AES-NI / FEAT_AES 8-block batched
// encrypt). No kernel deps, no allocator. `no_std` in production
// (host tests flip `std` on for libtest's panic=unwind harness).
//
// **What's inside**:
//
//   * [`Aes128GcmFast`] — pre-keyed seal / open / scatter-gather
//     seal. Per-record cost is one nonce-block AES encrypt + the
//     8-block stitched inner loop + the final tag XOR.
//   * [`ghash_batch`] — internal 8-way batched GHASH with
//     deferred polynomial reduction (Gueron 2010 §4 aggregated
//     Karatsuba). Used directly by `Aes128GcmFast` for the seal
//     hot path (stitched with AES-CTR XOR) and the open path
//     (batched-absorb-then-decrypt). Exposed publicly for
//     callers that want the raw GHASH primitive without the AES.
//
// **Performance** (measured on GCE n2-highcpu-4, AES-128-GCM TLS
// record-layer seal, server-side TSC cycles ÷ bytes encrypted):
//
//   workload              cy/B
//   static_16k_tls_max    1.84
//   static_64k_tls_max    1.76
//   static_256k_tls_max   1.61
//   static_1m_tls_max     1.64
//
// Down from the ~22 c/B baseline (per-block GHASH, two-pass
// AES-then-GHASH). The stitched per-chunk loop keeps every
// ciphertext block in xmm/neon registers from the AES-CTR XOR
// through the PCLMUL/PMULL accumulate, so each byte is touched
// exactly twice (PT load → CT store) instead of three times.
//
// **Cross-arch**: identical algorithm on every target; the math
// hardware acceleration comes from `_mm_clmulepi64_si128` on x86
// and `vmull_p64` / `vmull_high_p64` on aarch64 — paired with
// the `aes` crate's 8-way AES-NI (x86) / FEAT_AES (aarch64)
// backend. The portable software fallback exists only for
// targets without PCLMUL or PMULL (used by `cargo test` on
// emulated hosts; never reached on any deploy target).
//
// **Correctness**:
//
//   * NIST SP 800-38D §B Test Case 4 KAT.
//   * Sweep vs upstream audited `aes-gcm` crate (round-trip +
//     tamper detection across plaintext sizes 0..16383 + AAD
//     variants).
//   * Sweep vs upstream audited `ghash` crate (multi-chunk +
//     several H values).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod aes_gcm;
pub mod ghash_batch;

pub use aes_gcm::{Aes128GcmFast, KEY_LEN, NONCE_LEN, TAG_LEN};
