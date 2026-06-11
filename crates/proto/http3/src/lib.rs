// crates/proto/http3 — HTTP/3 server over //crates/proto/quic.
//
// Layered on top of `//crates/proto/quic`'s QuicConn / accept_stream / recv
// / send / close_stream API. Two concerns split by file:
//
//   frame.rs    RFC 9114 §7 frame types: DATA, HEADERS, SETTINGS.
//               Each frame is `varint type || varint length ||
//               payload`. Sans-io codec — pure byte-level.
//   qpack.rs    RFC 9204 QPACK with the static table only
//               (`SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`). Decoder
//               handles indexed / literal-with-name-reference /
//               literal-with-literal-name lines and Huffman-coded
//               string values; encoder emits literal-with-literal-
//               name + indexed for `:status`.
//   huffman.rs  RFC 7541 Appendix B static Huffman code tree
//               (shared with QPACK per RFC 9204 §4.1.4).
//   static_table.rs  The 99-entry QPACK static table (RFC 9204
//               Appendix A).
//   server.rs   `H3Server` — opens server-side control stream,
//               accepts client control + request streams, parses
//               H3 frames into `http::Request`, dispatches to
//               the user handler, encodes `http::Response`
//               back through QPACK + DATA + FIN.
//
// Public API (re-exported through this module's root):
//   * `listen(port, handler, cert, key)` — bind a UDP port,
//     terminate QUIC + HTTP/3, dispatch requests to `handler`.
//
// HTTPS handler model matches `http::listen` exactly:
// `H: AsyncFn(&Request) -> Response`. The same handler code can
// serve HTTP/1.1 over TCP+TLS and HTTP/3 over QUIC by wiring up
// both `http::listen_https` and `http3::listen` against
// the same closure.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod client;
pub mod diag;
pub mod frame;
pub mod huffman;
pub mod qpack;
pub mod server;
pub mod static_table;

pub use client::{H3ClientConn, H3ClientError, H3FetchError, H3Response, h3_connect, h3_fetch, h3_get};
pub use server::{ListenError, listen};

/// HTTP/3 application error codes (RFC 9114 §8.1) — carried in
/// RESET_STREAM / STOP_SENDING / CONNECTION_CLOSE(0x1d) frames.
pub mod errcode {
    /// No error: graceful shutdown / request cancel without blame.
    pub const H3_NO_ERROR: u64 = 0x0100;
    /// Internal error in the peer's HTTP stack — what the server
    /// resets a response stream with when a streaming handler errors
    /// mid-body.
    pub const H3_INTERNAL_ERROR: u64 = 0x0102;
    /// The client no longer wants this request/response.
    pub const H3_REQUEST_CANCELLED: u64 = 0x010c;
}
