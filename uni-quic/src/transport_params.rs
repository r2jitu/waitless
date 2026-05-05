// uni-quic/src/transport_params.rs — RFC 9000 §18 transport parameters.
//
// Endpoints exchange their flow-control / connection-level limits
// during the TLS handshake via the `quic_transport_parameters`
// extension (codepoint 0x39, RFC 9001 §8.2). Each parameter is a
// `(varint id, varint length, bytes value)` TLV; integer values
// use the QUIC variable-length integer encoding (`crate::wire`).
//
// This module covers the small subset HTTP/3 needs:
//
//   * `original_destination_connection_id` (server, mandatory)
//   * `initial_source_connection_id`       (both ends, mandatory)
//   * `initial_max_data`                   (per-conn flow control)
//   * `initial_max_stream_data_bidi_local`
//   * `initial_max_stream_data_bidi_remote`
//   * `initial_max_stream_data_uni`
//   * `initial_max_streams_bidi`
//   * `initial_max_streams_uni`
//   * `max_idle_timeout`
//
// Out of scope for the v1 server (until we need them):
//
//   * `stateless_reset_token`, `preferred_address`, `disable_active_migration`
//   * `max_udp_payload_size`, `ack_delay_exponent`, `max_ack_delay`
//   * `active_connection_id_limit`, `retry_source_connection_id`

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::wire::{read_varint, write_varint, WireError};

// ============================================================================
// Parameter IDs (RFC 9000 §18.2)
// ============================================================================

pub mod tp_id {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
}

// ============================================================================
// Outbound builder — server transport parameters
// ============================================================================

/// Values the server announces. Defaults match what HTTP/3 needs
/// for a small request/response: 256 KiB per stream, 1 MiB per
/// connection, up to 100 concurrent bidi streams. Override via the
/// public fields before calling `encode`.
pub struct ServerParams<'a> {
    /// Mandatory: the DCID the client put on its very first Initial
    /// (= the value used to derive Initial keys).
    pub original_destination_connection_id: &'a [u8],
    /// Mandatory: the SCID the server set on its first Initial reply
    /// (= our chosen `local_cid`).
    pub initial_source_connection_id: &'a [u8],
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout_ms: u64,
}

impl<'a> ServerParams<'a> {
    pub fn defaults(odcid: &'a [u8], iscid: &'a [u8]) -> Self {
        ServerParams {
            original_destination_connection_id: odcid,
            initial_source_connection_id: iscid,
            initial_max_data: 1 << 20,                      // 1 MiB
            initial_max_stream_data_bidi_local: 256 << 10,  // 256 KiB
            initial_max_stream_data_bidi_remote: 256 << 10, // 256 KiB
            initial_max_stream_data_uni: 256 << 10,         // 256 KiB
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_idle_timeout_ms: 30_000,
        }
    }

    /// Encode into `out` as a sequence of (id, len, value) TLVs.
    /// Returns bytes written. Caller wraps the result in the TLS
    /// extension envelope (`ext_type=0x39, ext_len:u16, bytes`).
    pub fn encode(&self, out: &mut Vec<u8>) {
        write_bytes_param(
            out,
            tp_id::ORIGINAL_DESTINATION_CONNECTION_ID,
            self.original_destination_connection_id,
        );
        write_bytes_param(
            out,
            tp_id::INITIAL_SOURCE_CONNECTION_ID,
            self.initial_source_connection_id,
        );
        write_varint_param(out, tp_id::INITIAL_MAX_DATA, self.initial_max_data);
        write_varint_param(
            out,
            tp_id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        );
        write_varint_param(
            out,
            tp_id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        );
        write_varint_param(
            out,
            tp_id::INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        );
        write_varint_param(
            out,
            tp_id::INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
        );
        write_varint_param(
            out,
            tp_id::INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
        );
        write_varint_param(out, tp_id::MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms);
    }
}

fn write_varint_param(out: &mut Vec<u8>, id: u64, value: u64) {
    let mut tmp = [0u8; 8];
    // id
    let n = write_varint(id, &mut tmp).expect("id fits in 8");
    out.extend_from_slice(&tmp[..n]);
    // measure value first so we can write the length VARINT
    let vn = write_varint(value, &mut tmp).expect("value fits in 8");
    // length VARINT
    let mut lbuf = [0u8; 8];
    let ln = write_varint(vn as u64, &mut lbuf).expect("len fits in 8");
    out.extend_from_slice(&lbuf[..ln]);
    out.extend_from_slice(&tmp[..vn]);
}

fn write_bytes_param(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    let mut tmp = [0u8; 8];
    let n = write_varint(id, &mut tmp).expect("id fits in 8");
    out.extend_from_slice(&tmp[..n]);
    let mut lbuf = [0u8; 8];
    let ln = write_varint(value.len() as u64, &mut lbuf).expect("len fits in 8");
    out.extend_from_slice(&lbuf[..ln]);
    out.extend_from_slice(value);
}

// ============================================================================
// Inbound parser — client transport parameters
// ============================================================================

/// Subset of client transport parameters the server cares about.
/// Anything we don't track is silently dropped on parse — RFC 9000
/// §18.1 requires endpoints to ignore unknown params.
#[derive(Default, Debug, Clone)]
pub struct ClientParams {
    pub initial_source_connection_id: Option<Vec<u8>>,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout_ms: u64,
}

#[derive(Debug)]
pub enum ParamsError {
    Wire,
}

impl From<WireError> for ParamsError {
    fn from(_: WireError) -> Self {
        ParamsError::Wire
    }
}

/// Parse a transport_parameters extension body. The input is the
/// TLV stream — the caller has already stripped the TLS extension
/// envelope (ext_type / ext_len).
pub fn parse_client_params(mut bytes: &[u8]) -> Result<ClientParams, ParamsError> {
    let mut out = ClientParams::default();
    while !bytes.is_empty() {
        let (id, n) = read_varint(bytes)?;
        bytes = &bytes[n..];
        let (len, n) = read_varint(bytes)?;
        bytes = &bytes[n..];
        let len = len as usize;
        if len > bytes.len() {
            return Err(ParamsError::Wire);
        }
        let value = &bytes[..len];
        bytes = &bytes[len..];

        match id {
            tp_id::INITIAL_SOURCE_CONNECTION_ID => {
                out.initial_source_connection_id = Some(value.to_vec());
            }
            tp_id::INITIAL_MAX_DATA => {
                out.initial_max_data = decode_varint_payload(value)?;
            }
            tp_id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                out.initial_max_stream_data_bidi_local = decode_varint_payload(value)?;
            }
            tp_id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                out.initial_max_stream_data_bidi_remote = decode_varint_payload(value)?;
            }
            tp_id::INITIAL_MAX_STREAM_DATA_UNI => {
                out.initial_max_stream_data_uni = decode_varint_payload(value)?;
            }
            tp_id::INITIAL_MAX_STREAMS_BIDI => {
                out.initial_max_streams_bidi = decode_varint_payload(value)?;
            }
            tp_id::INITIAL_MAX_STREAMS_UNI => {
                out.initial_max_streams_uni = decode_varint_payload(value)?;
            }
            tp_id::MAX_IDLE_TIMEOUT => {
                out.max_idle_timeout_ms = decode_varint_payload(value)?;
            }
            _ => {} // unknown / ignored
        }
    }
    Ok(out)
}

fn decode_varint_payload(v: &[u8]) -> Result<u64, ParamsError> {
    let (n, consumed) = read_varint(v)?;
    if consumed != v.len() {
        return Err(ParamsError::Wire);
    }
    Ok(n)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_params_round_trip() {
        let odcid = [0xa1u8; 8];
        let iscid = [0xb2u8; 8];
        let p = ServerParams::defaults(&odcid, &iscid);
        let mut buf = Vec::new();
        p.encode(&mut buf);
        let parsed = parse_client_params(&buf).expect("parse");
        assert_eq!(
            parsed.initial_source_connection_id.as_deref(),
            Some(&iscid[..])
        );
        assert_eq!(parsed.initial_max_data, 1 << 20);
        assert_eq!(parsed.initial_max_stream_data_bidi_remote, 256 << 10);
        assert_eq!(parsed.initial_max_streams_bidi, 100);
        assert_eq!(parsed.max_idle_timeout_ms, 30_000);
    }

    #[test]
    fn parse_ignores_unknown_id() {
        // id = 0x99 (unknown), len = 1, value = 0x42.
        let blob: &[u8] = &[0x40, 0x99, 0x01, 0x42];
        let parsed = parse_client_params(blob).expect("ignore unknown");
        assert!(parsed.initial_source_connection_id.is_none());
    }

    #[test]
    fn parse_rejects_truncated_value() {
        // id = 0x04 (initial_max_data), len = 8, only 4 bytes follow.
        let blob: &[u8] = &[0x04, 0x08, 0x01, 0x02, 0x03, 0x04];
        assert!(parse_client_params(blob).is_err());
    }
}
