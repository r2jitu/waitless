// uni-tls/src/quic — QUIC v1 server implementation.
//
// Top-level structure:
//
//   tls.rs    — TLS 1.3 handshake driver in CRYPTO-frame I/O mode.
//               Reuses every primitive in `//net:tls`; only the
//               wrapping changes from TLS records to per-level
//               byte queues. (`QuicTls`)
//   conn.rs   — Per-connection state machine. Owns the keys for
//               all three packet number spaces, drives `QuicTls`,
//               assembles outbound packets (AEAD seal + HP
//               protect) and parses inbound (HP unprotect + AEAD
//               open + frame dispatch). Sans-io. (`Connection`)
//   inbox.rs  — Per-connection async queue: the listener task
//               pushes routed UDP datagrams; the conn task awaits
//               them. Single-worker, RefCell-based. (`ConnInbox`)
//   server.rs — UDP listener task. Receives datagrams, decodes
//               DCID, routes to the right conn task via slot-
//               encoded DCID lookup. Spawns one task per
//               connection. (`QuicListener`, `quic_listen`)
//
// Why the QUIC code lives under `uni-tls`: `QuicTls` reuses the
// same `KeySchedule` / `Transcript` / cert + signing key types as
// the TLS-over-TCP server, and the connection layer wires those
// up. A future split into `//uni-quic` is plausible once a
// QUIC client lands or HTTP/3 grows enough surface, but the
// current shape minimises crate proliferation while keeping the
// code well-scoped: everything QUIC-specific is under this
// directory, and `uni_tls::server::*` stays focused on
// TLS-over-TCP.
//
// Public API (re-exported through `uni_tls::quic::*`):
//   * `quic_listen(port, cert, key, handler)` — bind a UDP port,
//     terminate QUIC connections, dispatch each new connection
//     to `handler` running as `async fn(QuicConn) -> ()`.
//   * `QuicConn` — handle the handler receives. Currently a
//     thin wrapper around `Connection` with HANDSHAKE_DONE +
//     state inspection; future commits add `accept_stream` /
//     `recv` / `send`.
//   * `ConnError` (re-exported from conn.rs)
//   * Slot-encoding constants (`SERVER_CID_LEN`) for tests +
//     debug tooling.

pub mod conn;
pub mod inbox;
pub mod tls;
pub mod server;

pub use conn::{ConnError, ConnState, Connection, ConnectionId, SERVER_CID_LEN};
pub use inbox::ConnInbox;
pub use server::{QuicConn, QuicListenError, QuicListener};
pub use tls::{CryptoLevel, QuicTls, QuicTlsError, QuicTlsState};
