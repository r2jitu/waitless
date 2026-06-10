// crates/proto/quic — QUIC v1 protocol stack (RFC 9000 + RFC 9001).
//
// Owns the FULL QUIC implementation: sans-io wire-format primitives
// (`wire`, `frame`, `crypto`), the TLS 1.3 handshake driver wrapped
// over CRYPTO frames (`tls`), the per-connection state machine
// (`conn`), per-connection async inbox (`inbox`), and the UDP
// endpoint that routes datagrams to conn tasks (`endpoint`).
// Depends on `//crates/proto/tls` for the sans-io TLS bits (`schedule`,
// `aead`, `handshake`) plus the cert / signing-key types reused
// across both protocols.
//
// Module layout (flat under `src/`):
//
//   lib.rs       crate root: no_std + module declarations.
//   wire.rs      VARINT codec, long/short header parsing, packet
//                  number truncation/reconstruction (sans-io).
//   frame.rs     RFC 9000 §19 frame codec (PADDING / PING / ACK /
//                  CRYPTO / STREAM / CONNECTION_CLOSE / HANDSHAKE_DONE).
//   crypto.rs    RFC 9001 packet protection: Initial keys, AEAD
//                  seal/open (AES-128-GCM + ChaCha20-Poly1305),
//                  header protection masks.
//   tls.rs       TLS 1.3 handshake driver in CRYPTO-frame I/O mode
//                  (`QuicTls`). Reuses every primitive in `//crates/proto/tls`;
//                  only the wrapping changes from TLS records to
//                  per-level byte queues.
//   conn.rs      Per-connection state machine. Owns the keys for
//                  all three packet number spaces, drives `QuicTls`,
//                  assembles outbound packets and parses inbound.
//                  Sans-io. (`Connection`)
//   inbox.rs     Per-connection async queue: the endpoint task
//                  pushes routed UDP datagrams; the conn task awaits
//                  them. Single-worker, RefCell-based. (`ConnInbox`)
//   endpoint.rs  UDP endpoint task. Receives datagrams, decodes
//                  DCID, routes to the right conn task via slot-
//                  encoded DCID lookup. Spawns one task per
//                  connection. (`QuicListener`, `quic_listen`).
//                  Future: `connect()` for the QUIC client role
//                  lives in this same module — the endpoint owns
//                  the UDP socket + slot table for both directions.
//
// Public API (re-exported through this crate's root):
//   * `quic_listen(port, cert, key, handler)` — bind a UDP port,
//     terminate QUIC connections, dispatch each new connection
//     to `handler` running as `async fn(QuicConn) -> ()`.
//   * `QuicConn` — handle the handler receives.
//   * `ConnError`
//   * Slot-encoding constants (`SERVER_CID_LEN`) for tests +
//     debug tooling.

// Stays no_std in production; flips to std only under `--test`
// so the libtest harness has the std it needs.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod conn;
pub mod crypto;
pub mod diag;
pub mod egress;
mod drr;
pub mod endpoint;
pub mod frame;
pub mod inbox;
pub mod streams;
mod time;
pub mod tls;
pub mod transport_params;
pub mod wire;

pub use conn::{ConnError, ConnState, Connection, ConnectionId, SERVER_CID_LEN};
pub use endpoint::{QuicConn, QuicListenError, QuicListener, quic_listen};
pub use inbox::ConnInbox;
pub use tls::{CryptoLevel, QuicTls, QuicTlsError, QuicTlsState};

/// Force-exercise every QUIC + TLS primitive that lazily allocates
/// inside its RustCrypto crate so the heap allocations land in
/// `HEAP_BASELINE` at boot rather than being charged to the first
/// connection as a per-conn delta. Idempotent.
///
/// Today this delegates entirely to [`::tls::preinit`] — every
/// QUIC primitive that allocates lazily (ECDSA, ChaCha20-Poly1305,
/// X25519) lives inside the TLS sans-io modules. If a future QUIC-
/// only primitive (e.g. AES-128-GCM for Initial-packet protection)
/// ever grows its own lazy state, the exercise for it goes here.
pub fn preinit() {
    ::tls::preinit();
}
