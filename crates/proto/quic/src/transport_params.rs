// crates/proto/quic/src/transport_params.rs — RFC 9000 §18 transport parameters.
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

use alloc::vec::Vec;

use crate::wire::{WireError, read_varint, write_varint};

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

/// Values the server announces. Defaults size the initial receive
/// window so a typical upload fits without mid-transfer
/// MAX_STREAM_DATA replenishment: 2 MiB per stream, 8 MiB per
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
    /// RFC 9000 §7.3: a server that sent a Retry MUST echo the SCID
    /// it chose on that Retry. Our server never sends Retry, so this
    /// is always `None` in production (encoding unchanged); the
    /// client-role §7.3 validation tests drive the `Some` arm.
    pub retry_source_connection_id: Option<&'a [u8]>,
}

impl<'a> ServerParams<'a> {
    pub fn defaults(odcid: &'a [u8], iscid: &'a [u8]) -> Self {
        ServerParams {
            original_destination_connection_id: odcid,
            initial_source_connection_id: iscid,
            retry_source_connection_id: None,
            initial_max_data: crate::streams::INITIAL_MAX_DATA,
            initial_max_stream_data_bidi_local: crate::streams::INITIAL_MAX_STREAM_DATA,
            initial_max_stream_data_bidi_remote: crate::streams::INITIAL_MAX_STREAM_DATA,
            initial_max_stream_data_uni: crate::streams::INITIAL_MAX_STREAM_DATA,
            // Initial bidi-stream credit. The peer can open this
            // many bidirectional streams before they MUST stop and
            // wait for a MAX_STREAMS frame from us. We replenish
            // continuously as streams complete (see
            // `Connection::flush_outbound`'s MAX_STREAMS emission),
            // so the only visible effect of this initial value is
            // the headroom available before the first replenishment
            // round-trip. 1024 is comfortably more than any
            // single-page web app's burst.
            initial_max_streams_bidi: 1024,
            initial_max_streams_uni: 1024,
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
        if let Some(rscid) = self.retry_source_connection_id {
            write_bytes_param(out, tp_id::RETRY_SOURCE_CONNECTION_ID, rscid);
        }
    }
}

// ============================================================================
// Outbound builder — client transport parameters
// ============================================================================

/// Encode the CLIENT role's transport parameters (RFC 9000 §18.2) —
/// sensible mirrors of [`ServerParams::defaults`]. The client never
/// sends the server-only params (`original_destination_connection_id`,
/// `stateless_reset_token`, `retry_source_connection_id`, …); it adds
/// the receive-side tuning the server omits (`max_udp_payload_size`,
/// `ack_delay_exponent`, `max_ack_delay`, `active_connection_id_limit`).
/// `iscid` is the SCID the client puts on its first Initial. The blob
/// goes into the ClientHello's `quic_transport_parameters` extension
/// (RFC 9001 §8.2).
pub fn encode_client_params(out: &mut Vec<u8>, iscid: &[u8]) {
    write_bytes_param(out, tp_id::INITIAL_SOURCE_CONNECTION_ID, iscid);
    // Our RX path handles full-MTU datagrams; advertise the standard
    // 1500-minus-IP/UDP envelope.
    write_varint_param(out, tp_id::MAX_UDP_PAYLOAD_SIZE, 1452);
    write_varint_param(out, tp_id::INITIAL_MAX_DATA, crate::streams::INITIAL_MAX_DATA);
    write_varint_param(
        out,
        tp_id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        crate::streams::INITIAL_MAX_STREAM_DATA,
    );
    write_varint_param(
        out,
        tp_id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        crate::streams::INITIAL_MAX_STREAM_DATA,
    );
    write_varint_param(
        out,
        tp_id::INITIAL_MAX_STREAM_DATA_UNI,
        crate::streams::INITIAL_MAX_STREAM_DATA,
    );
    // MUST match `Connection`'s `peer_max_streams_*_advertised` seeds
    // (the same coupling `ServerParams::defaults` documents).
    write_varint_param(out, tp_id::INITIAL_MAX_STREAMS_BIDI, 1024);
    write_varint_param(out, tp_id::INITIAL_MAX_STREAMS_UNI, 1024);
    // RFC defaults made explicit: 2^3 µs ACK-delay units, 25 ms max.
    write_varint_param(out, tp_id::ACK_DELAY_EXPONENT, 3);
    write_varint_param(out, tp_id::MAX_ACK_DELAY, 25);
    // §18.2: MUST be ≥ 2.
    write_varint_param(out, tp_id::ACTIVE_CONNECTION_ID_LIMIT, 2);
    write_varint_param(out, tp_id::MAX_IDLE_TIMEOUT, 30_000);
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
///
/// Also reused by the CLIENT role to parse the SERVER's parameters
/// out of EncryptedExtensions (the TLV stream is direction-agnostic);
/// the two trailing CID fields below only ever appear in that
/// direction and feed the client's RFC 9000 §7.3 authentication.
#[derive(Debug, Clone)]
pub struct ClientParams {
    pub initial_source_connection_id: Option<Vec<u8>>,
    /// Server→client only (RFC 9000 §18.2 `0x00`): the DCID of the
    /// client's first Initial, echoed for §7.3 authentication.
    pub original_destination_connection_id: Option<Vec<u8>>,
    /// Server→client only (`0x10`): the SCID the server chose on its
    /// Retry, echoed for §7.3 authentication. Present iff a Retry
    /// was sent.
    pub retry_source_connection_id: Option<Vec<u8>>,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout_ms: u64,
    /// RFC 9000 §18.2 `ack_delay_exponent` (0x0a): the peer's ACK
    /// `ack_delay` fields are in `2^exponent` µs units. Default 3
    /// (8 µs units); values above 20 are a protocol violation.
    pub ack_delay_exponent: u8,
    /// RFC 9000 §18.2 `max_ack_delay` (0x0b), in milliseconds: the
    /// longest the peer will intentionally delay an ACK — feeds our
    /// PTO and caps the `ack_delay` honored in RTT samples. Default
    /// 25; values ≥ 2^14 are a protocol violation.
    pub max_ack_delay_ms: u64,
}

/// The RFC 9000 §18.2 defaults apply both when a parameter is absent
/// from the peer's extension and before any extension is parsed, so
/// `default()` carries them — a derived all-zeros default would
/// silently misscale every ACK delay.
impl Default for ClientParams {
    fn default() -> Self {
        ClientParams {
            initial_source_connection_id: None,
            original_destination_connection_id: None,
            retry_source_connection_id: None,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            max_idle_timeout_ms: 0,
            ack_delay_exponent: 3,
            max_ack_delay_ms: 25,
        }
    }
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
            tp_id::ORIGINAL_DESTINATION_CONNECTION_ID => {
                out.original_destination_connection_id = Some(value.to_vec());
            }
            tp_id::RETRY_SOURCE_CONNECTION_ID => {
                out.retry_source_connection_id = Some(value.to_vec());
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
            tp_id::ACK_DELAY_EXPONENT => {
                let v = decode_varint_payload(value)?;
                // RFC 9000 §18.2: values above 20 are invalid — a peer
                // sending one MUST be treated as a protocol violation
                // (TRANSPORT_PARAMETER_ERROR; surfaced as a parse error).
                if v > 20 {
                    return Err(ParamsError::Wire);
                }
                out.ack_delay_exponent = v as u8;
            }
            tp_id::MAX_ACK_DELAY => {
                let v = decode_varint_payload(value)?;
                // RFC 9000 §18.2: 2^14 ms or more is invalid.
                if v >= 1 << 14 {
                    return Err(ParamsError::Wire);
                }
                out.max_ack_delay_ms = v;
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
        assert_eq!(parsed.initial_max_data, 8 << 20);
        assert_eq!(parsed.initial_max_stream_data_bidi_remote, 2 << 20);
        assert_eq!(parsed.initial_max_streams_bidi, 1024);
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

    /// RFC 9000 §18.2: ack_delay_exponent (0x0a) + max_ack_delay (0x0b)
    /// parse into the params; absent → the RFC defaults (3, 25 ms);
    /// out-of-range values are protocol violations.
    #[test]
    fn parse_ack_delay_params() {
        // Absent → defaults.
        let parsed = parse_client_params(&[]).expect("empty parses");
        assert_eq!(parsed.ack_delay_exponent, 3, "default exponent");
        assert_eq!(parsed.max_ack_delay_ms, 25, "default max_ack_delay");

        // exponent = 10 (1-byte varint), max_ack_delay = 100 ms (100 ≥ 64
        // so it takes the 2-byte varint form 0x40 0x64).
        let blob: &[u8] = &[0x0a, 0x01, 0x0a, 0x0b, 0x02, 0x40, 0x64];
        let parsed = parse_client_params(blob).expect("parse");
        assert_eq!(parsed.ack_delay_exponent, 10);
        assert_eq!(parsed.max_ack_delay_ms, 100);

        // exponent 21 (> 20) is invalid.
        let blob: &[u8] = &[0x0a, 0x01, 0x15];
        assert!(parse_client_params(blob).is_err(), "exponent > 20 rejected");

        // max_ack_delay = 2^14 ms is invalid (2-byte varint 0x4000
        // encodes 0... use 16384 = varint 0x80 0x00 0x40 0x00).
        let blob: &[u8] = &[0x0b, 0x04, 0x80, 0x00, 0x40, 0x00];
        assert!(
            parse_client_params(blob).is_err(),
            "max_ack_delay >= 2^14 rejected"
        );
    }
}
