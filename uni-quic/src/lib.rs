// uni-quic — QUIC v1 protocol stack (RFC 9000 + RFC 9001).
//
// Owns the FULL QUIC implementation: sans-io wire-format primitives
// (`wire`, `frame`, `crypto`), the TLS 1.3 handshake driver wrapped
// over CRYPTO frames (`tls`), the per-connection state machine
// (`conn`), per-connection async inbox (`inbox`), and the UDP
// endpoint that routes datagrams to conn tasks (`endpoint`).
// Depends on `//uni-tls` for the sans-io TLS bits (`schedule`,
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
//                  (`QuicTls`). Reuses every primitive in `//uni-tls`;
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

// Stays no_std in production. Under `bazel test`, the
// `tests_need_std` flag flips this crate's `std` feature on so
// libtest's panic=unwind harness can link past the RustCrypto
// deps' no_std requirement.
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

extern crate alloc;

pub mod conn;
pub mod crypto;
pub mod diag;
pub mod endpoint;
pub mod frame;
pub mod inbox;
pub mod streams;
pub mod tls;
pub mod transport_params;
pub mod wire;

pub use conn::{ConnError, ConnState, Connection, ConnectionId, SERVER_CID_LEN};
pub use endpoint::{quic_listen, QuicConn, QuicListenError, QuicListener};
pub use inbox::ConnInbox;
pub use tls::{CryptoLevel, QuicTls, QuicTlsError, QuicTlsState};
