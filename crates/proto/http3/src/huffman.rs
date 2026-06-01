// crates/proto/http3/src/huffman.rs — re-export of the shared
// RFC 7541 Huffman codec.
//
// The field-compression Huffman code is identical for HPACK (HTTP/2)
// and QPACK (HTTP/3, RFC 9204 §4.1.4), so the table + decoder now live
// in the leaf crate `//crates/proto/field-huffman` and are shared by
// `proto/http2` and `proto/http3`. This module re-exports the public
// surface so existing `crate::huffman::…` call sites (qpack.rs,
// server.rs) keep working unchanged.

pub use field_huffman::{HuffmanError, decode, decode_into_slice, preinit};
