// crates/proto/http2 — server-role HTTP/2 (RFC 7540 + HPACK RFC 7541).
//
// Layered on the shared `proto/http` core (Request / Response /
// BodyReader / handler API) and generic over the byte stream
// (`http::HttpStream`), exactly like `proto/http`'s own `serve_conn`.
// It therefore needs *no* transport dependency — no tls, tcp, or quic —
// so plain-H1.1 consumers never transitively pull a transport in.
// `proto/tls` depends on this crate and dispatches here when ALPN
// negotiates "h2"; HTTP/1.1 stays the golden path and the ALPN default.
//
// Module layout (flat under `src/`):
//
//   frame.rs         RFC 7540 §4-6 frame codec (9-byte header + payload).
//   hpack.rs         HPACK (RFC 7541) — dynamic-table decoder (the
//                      correctness-critical half) + a stateless encoder.
//   static_table.rs  The 61-entry HPACK static table (RFC 7541 App. A).
//   server.rs        `serve_conn` — connection preface, SETTINGS, the
//                      multiplexing serve loop, connection + per-stream
//                      flow control, and the P0 DoS caps.
//   diag.rs          `http2::diag` observability block (`/obs`).
//
// The RFC 7541 Huffman code is shared with `proto/http3` (QPACK) via the
// `//crates/proto/field-huffman` leaf crate.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod diag;
pub mod frame;
pub mod hpack;
pub mod server;
pub mod static_table;

pub use server::serve_conn;
