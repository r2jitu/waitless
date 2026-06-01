// crates/proto/http2 — the HTTP/2 server (RFC 7540 + HPACK RFC 7541).
//
// "h2" is HTTP/2 *over TLS* (RFC 7540 §3.1; the cleartext "h2c" variant
// is a non-goal), so this crate *is* an HTTPS server, and — because
// ALPN mandates an HTTP/1.1 fallback — it necessarily serves h1.1 too.
// `http2::listen` is the one-call TLS/TCP listener; it drives the TLS
// handshake (via `proto/tls`), reads the negotiated ALPN, and runs this
// crate's `serve_conn` (h2) or `http::serve_conn` (h1.1, the golden
// path + fallback).
//
// This mirrors `proto/http3` (which bundles its QUIC listener with the
// h3 protocol): `http` / `http2` / `http3` are each "the server for
// that HTTP version over its transport" — plaintext TCP, TLS/TCP, and
// QUIC/UDP respectively. The wire logic rides the shared `proto/http`
// core and `serve_conn` stays generic over `http::HttpStream`, so the
// protocol half can serve any byte stream; only `listen` binds TLS/TCP.
//
// Module layout (flat under `src/`):
//
//   frame.rs         RFC 7540 §4-6 frame codec (9-byte header + payload).
//   hpack.rs         HPACK (RFC 7541) — dynamic-table decoder (the
//                      correctness-critical half) + a stateless encoder.
//   static_table.rs  The 61-entry HPACK static table (RFC 7541 App. A).
//   server.rs        `serve_conn` — connection preface, SETTINGS, the
//                      multiplexing serve loop, connection + per-stream
//                      flow control, and the P0 DoS caps. Transport-
//                      agnostic (generic over `http::HttpStream`).
//   listen.rs        `listen` — the TLS/TCP listener + `TlsStream`
//                      adapter + conn pool + ALPN dispatch.
//   diag.rs          `http2::diag` observability block (`/obs`).
//
// The RFC 7541 Huffman code is shared with `proto/http3` (QPACK) via the
// `//crates/proto/field-huffman` leaf crate.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod diag;
pub mod frame;
pub mod hpack;
pub mod listen;
pub mod server;
pub mod static_table;

pub use listen::{ListenError, TlsStream, listen};
pub use server::serve_conn;
