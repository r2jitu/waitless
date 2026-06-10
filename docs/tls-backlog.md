# TLS 1.3 — conformance + hardening backlog

Last updated 2026-05-31.

Consolidates the TLS 1.3 server gaps that were scattered across
`proto/tls/src/server.rs` (header comment), `ticket.rs`, and
[`roadmap.md`](roadmap.md) (deferred items). The server (`proto/tls`) is a
hand-rolled, sans-io TLS 1.3 implementation; its build history is in
[`design-history.md`](design-history.md).

## What's implemented (don't re-propose)

Full TLS 1.3 handshake over **X25519** KEX with an **ECDSA P-256 + SHA-256**
server cert; **TLS_AES_128_GCM_SHA256** record protection; **ALPN**
negotiation (`handlers.rs`, prefers `h2`, falls back to `http/1.1`); **1-RTT
session resumption** — NewSessionTicket issued every handshake, returning
PSK resumed via `try_resume` with binder verification, skipping the
Certificate/CertVerify flight (`test_https_session_resumption`); a 0-RTT
**replay cache** (`replay.rs`, used by the QUIC path). Drives real
browsers / curl / openssl in production.

## Gaps — priority order

### Pending — real, server-affecting

- **TL-1 — HelloRetryRequest (RFC 8446 §4.1.4) — P1.** No HRR path: if a
  ClientHello offers no X25519 key_share (e.g. a client that prefers a
  different group first, or sends an empty key_share to probe), the
  handshake fails instead of asking for X25519 via HRR. Browsers send an
  X25519 key_share by default so it works in practice, but a
  non-default-ordered client breaks. **Effort: M.**
- **TL-2 — Key update (RFC 8446 §4.6.3) — P2.** No `KeyUpdate` post-
  handshake message. AES-GCM has a per-key record limit (~2³⁴.5 records);
  a long-lived connection moving a lot of data should rekey. Low urgency
  for a request/response server (connections are short), real for bulk /
  long-lived streams. **Effort: M.**
- **TL-3 — Ticket key rotation — P2.** `ticket.rs` is single-key, no
  rotation: the ticket-sealing key is generated once and lives for the
  process. A 2-key ring (new key seals, old key still opens within a
  window) is needed so resumption survives key roll without a
  resumption-storm. **Effort: M.**
- **TL-4 — Cipher / curve breadth — P3.** Only `TLS_AES_128_GCM_SHA256` +
  X25519. No AES-256-GCM (for clients/policies that require it), no
  secondary group. ChaCha20-Poly1305 was deliberately dropped (broken
  `chacha20` v0.9.1 SIMD on `x86_64-unknown-none` + browsers prefer AES) —
  see `aead.rs`; don't re-add without fixing that. Single-suite is fine
  for the current client set; breadth is a compatibility/policy item.
  **Effort: M.**

### Production-readiness (cross-cut, owned by roadmap "Deferred")

- **TL-5 — Production CSPRNG — mostly landed.** `kernel::rng`
  (`crates/kernel/bare/src/rng.rs`) is now a SHA-256 Hash_DRBG with
  **periodic reseed** (fresh entropy folded every 1 MiB of output) and
  **multi-source HW** (RDSEED/RDRAND on x86_64, aarch64 RNDR);
  `kernel_core::entropy_health` runs the NIST SP 800-90B startup health
  tests + an MCV min-entropy estimate, surfaced via `/obs`
  (`rng_min_entropy_mbits` / `rng_rct_pass` / `rng_apt_pass`). What
  remains is a virtio-rng / aarch64 RNDRRS collector and a certified
  offline min-entropy bound. → [`roadmap.md`](roadmap.md).
- **TL-6 — Real wall-clock time — landed (x86).** `kernel_core::clock`
  reads the x86 CMOS RTC at boot and exposes `wall_unix_secs()` /
  `civil_to_unix_secs`, surfaced via `/obs` (`wall_unix_secs`); ticket
  lifetimes and (future) cert validity windows now have absolute time.
  aarch64 PL031 is the only remainder. → [`roadmap.md`](roadmap.md).
- **TL-7 — Faster ECDSA — P3 (perf, not conformance).** `cv_sign` is the
  cold-handshake hotspot; `fiat-p256` (~2×) or `ring` (5–10×, build pain)
  are the levers. Less urgent now that resumption skips the signature on
  warm conns. → [`roadmap.md`](roadmap.md).

### Deferred by design

- **TL-8 — 0-RTT early data over TCP.** The NewSessionTicket carries no
  `early_data` extension, so resumption is 1-RTT only. 0-RTT is
  replay-sensitive (RFC 8446 §8 / RFC 8470); enabling it needs per-route
  idempotent-GET-only gating + the nonce cache. Keep deferred unless a
  repeat-visit-heavy, all-GET, RTT-bound workload justifies it. The
  `replay.rs` machinery already exists (for QUIC).

## Non-goals

- **Client authentication (mTLS)** — out of scope for a public web server.
- **TLS 1.2 / earlier** — TLS 1.3 only, by design.
- **Renegotiation** — removed in TLS 1.3; not applicable.

## References

- [`conformance-roadmap.md`](conformance-roadmap.md) — RFC 9001 (TLS over
  QUIC) reuses `net_tls_crypto` / `net_tls_handshake`; key-update (TL-2)
  also appears there for the QUIC path.
- [`roadmap.md`](roadmap.md) — the deferred production-readiness items
  (RNG, wall-clock, ECDSA perf) with their "why now" triggers.
- [`http2-backlog.md`](http2-backlog.md) — H2 requires adding `"h2"` to the
  already-built ALPN negotiation.
