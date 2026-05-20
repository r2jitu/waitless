// net/dhcp_parse.rs — DHCP option TLV parser + reply classifier.
//
// Pure byte-slice logic (no driver / kernel / runtime deps) so this
// file compiles standalone as a `rust_test` target. The state-
// machine wrapper in `dhcp.rs` is a thin adapter over this module
// — the hard work (tolerating truncated options, unknown codes,
// missing end-markers, wrong magic cookies) lives here and is
// exhaustively unit-tested.

// ── Wire constants ───────────────────────────────────────────────────
pub const OP_BOOTREPLY: u8 = 2;
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

pub const MSG_OFFER: u8 = 2;
pub const MSG_ACK: u8 = 5;
pub const MSG_NAK: u8 = 6;

// DHCP option codes we care about.
const OPT_PAD: u8 = 0;
const OPT_SUBNET: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_END: u8 = 255;

// ── Parsed payload ───────────────────────────────────────────────────

/// Options we extracted from a DHCP reply. `None` for any option
/// that wasn't present (or was present but malformed — length-short
/// option values are skipped rather than reported).
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct ParsedOptions {
    pub msg_type: u8,
    pub subnet: Option<[u8; 4]>,
    pub gateway: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
    pub server_id: Option<[u8; 4]>,
}

/// Walk a DHCP options blob and extract the fields we care about.
///
/// Tolerates:
///   * Pad (0x00) bytes interleaved anywhere.
///   * Missing End (0xff) marker — walker stops at `opts.len()`.
///   * Truncated options (len byte says N but buffer has <N bytes)
///     — walker bails, returning what it already parsed.
///   * Unknown option codes — skipped via `len` with no mutation.
///   * Options present but too short to hold their documented
///     payload (e.g. Subnet with 2 bytes) — ignored silently.
pub fn parse_options(opts: &[u8]) -> ParsedOptions {
    let mut out = ParsedOptions::default();

    let mut i = 0;
    while i < opts.len() {
        let code = opts[i];
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            i += 1;
            continue;
        }
        // Need at least one byte for length.
        if i + 1 >= opts.len() {
            break;
        }
        let len = opts[i + 1] as usize;
        // Truncated option — value overflows remaining buffer.
        if i + 2 + len > opts.len() {
            break;
        }
        let val = &opts[i + 2..i + 2 + len];

        match code {
            OPT_SUBNET if val.len() >= 4 => out.subnet = Some([val[0], val[1], val[2], val[3]]),
            OPT_ROUTER if val.len() >= 4 => out.gateway = Some([val[0], val[1], val[2], val[3]]),
            OPT_DNS if val.len() >= 4 => out.dns = Some([val[0], val[1], val[2], val[3]]),
            OPT_MSG_TYPE if val.len() >= 1 => out.msg_type = val[0],
            OPT_SERVER_ID if val.len() >= 4 => {
                out.server_id = Some([val[0], val[1], val[2], val[3]])
            }
            _ => {}
        }

        i += 2 + len;
    }

    out
}

/// Validate the fixed-size DHCP reply header. Returns `None` if the
/// buffer is too short, the op is not BOOTREPLY, the magic cookie
/// doesn't match, or the transaction id doesn't match `expected_xid`.
///
/// The returned `yiaddr` is the "your" address from the reply — the
/// IP the server is offering / acknowledging.
pub fn validate_header(dhcp_bytes: &[u8], expected_xid_be: [u8; 4]) -> Option<[u8; 4]> {
    // DHCP fixed header is 240 bytes (236 BOOTP + 4 magic cookie).
    if dhcp_bytes.len() < 240 {
        return None;
    }
    if dhcp_bytes[0] != OP_BOOTREPLY {
        return None;
    }
    // Transaction id at offset 4..8 (network byte order on the wire).
    if dhcp_bytes[4..8] != expected_xid_be {
        return None;
    }
    // Magic cookie at offset 236..240.
    if dhcp_bytes[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }
    // yiaddr at offset 16..20 (4 bytes).
    Some([
        dhcp_bytes[16],
        dhcp_bytes[17],
        dhcp_bytes[18],
        dhcp_bytes[19],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_options: happy paths ───────────────────────────────────

    #[test]
    fn parses_offer_with_full_option_set() {
        // Typical DHCP OFFER from dnsmasq: msg_type(53)=OFFER,
        // subnet(1), router(3), dns(6), server_id(54), end(255).
        let opts: &[u8] = &[
            53, 1, MSG_OFFER, 1, 4, 255, 255, 255, 0, 3, 4, 10, 20, 30, 1, 6, 4, 10, 20, 30, 1, 54,
            4, 10, 20, 30, 2, 255,
        ];
        let got = parse_options(opts);
        assert_eq!(
            got,
            ParsedOptions {
                msg_type: MSG_OFFER,
                subnet: Some([255, 255, 255, 0]),
                gateway: Some([10, 20, 30, 1]),
                dns: Some([10, 20, 30, 1]),
                server_id: Some([10, 20, 30, 2]),
            }
        );
    }

    #[test]
    fn parses_ack_with_minimal_options() {
        // Some servers send ACK with just msg_type + server_id.
        // Missing subnet/gateway/dns must stay `None` — callers
        // treat those as "keep whatever OFFER gave us".
        let opts: &[u8] = &[53, 1, MSG_ACK, 54, 4, 10, 0, 0, 1, 255];
        let got = parse_options(opts);
        assert_eq!(got.msg_type, MSG_ACK);
        assert_eq!(got.server_id, Some([10, 0, 0, 1]));
        assert_eq!(got.subnet, None);
        assert_eq!(got.gateway, None);
        assert_eq!(got.dns, None);
    }

    #[test]
    fn parses_nak_with_no_data_options() {
        let opts: &[u8] = &[53, 1, MSG_NAK, 255];
        let got = parse_options(opts);
        assert_eq!(got.msg_type, MSG_NAK);
        assert_eq!(got.subnet, None);
    }

    // ── parse_options: option ordering + pad handling ───────────────

    #[test]
    fn tolerates_pad_bytes_between_options() {
        // RFC 2132: Pad (0x00) may appear between options as alignment.
        let opts: &[u8] = &[
            0, 0, // pad pad
            53, 1, MSG_OFFER, 0, // pad
            1, 4, 255, 255, 255, 0, 255,
        ];
        let got = parse_options(opts);
        assert_eq!(got.msg_type, MSG_OFFER);
        assert_eq!(got.subnet, Some([255, 255, 255, 0]));
    }

    #[test]
    fn skips_unknown_option_codes() {
        // Option 42 = NTP servers. We don't care but must advance
        // past it correctly and still find options after it.
        let opts: &[u8] = &[
            42, 4, 10, 0, 0, 3, // unknown (to us)
            53, 1, MSG_OFFER, 255,
        ];
        let got = parse_options(opts);
        assert_eq!(got.msg_type, MSG_OFFER);
    }

    // ── parse_options: malformed input ──────────────────────────────

    #[test]
    fn stops_at_implicit_end_when_no_end_marker() {
        // No 255 terminator; walker must bail at opts.len() without
        // reading past the slice.
        let opts: &[u8] = &[53, 1, MSG_OFFER, 1, 4, 255, 255, 255, 0];
        let got = parse_options(opts);
        assert_eq!(got.msg_type, MSG_OFFER);
        assert_eq!(got.subnet, Some([255, 255, 255, 0]));
    }

    #[test]
    fn rejects_option_with_length_overflowing_buffer() {
        // len=10 but only 2 payload bytes remain after the len
        // byte. Walker must stop without reading the bogus bytes.
        let opts: &[u8] = &[
            53, 1, MSG_OFFER, // good option
            1, 10, 1,
            2, // subnet with bogus len=10
               // (walker stops here; the subnet option is dropped)
        ];
        let got = parse_options(opts);
        assert_eq!(got.msg_type, MSG_OFFER);
        // Subnet was invalid — ignored, not `Some([1,2,_,_])`.
        assert_eq!(got.subnet, None);
    }

    #[test]
    fn rejects_option_code_with_no_length_byte() {
        // Trailing option code with no length byte is malformed.
        let opts: &[u8] = &[53, 1, MSG_OFFER, 1 /* no len */];
        let got = parse_options(opts);
        assert_eq!(got.msg_type, MSG_OFFER);
        assert_eq!(got.subnet, None);
    }

    #[test]
    fn ignores_option_with_len_too_short_for_payload() {
        // Subnet declares len=2 — valid TLV but not enough bytes
        // for a 4-byte IPv4. Must be skipped (not a panic, not a
        // partial-octet IP).
        let opts: &[u8] = &[
            1, 2, 0xaa, 0xbb, // subnet with broken short value
            53, 1, MSG_OFFER, 255,
        ];
        let got = parse_options(opts);
        assert_eq!(got.msg_type, MSG_OFFER);
        assert_eq!(got.subnet, None);
    }

    #[test]
    fn empty_option_blob_returns_default() {
        let got = parse_options(&[]);
        assert_eq!(got, ParsedOptions::default());
        assert_eq!(got.msg_type, 0);
    }

    #[test]
    fn only_end_marker_returns_default() {
        let got = parse_options(&[255]);
        assert_eq!(got, ParsedOptions::default());
    }

    // ── validate_header ─────────────────────────────────────────────

    /// Build a valid DHCP reply header (240 bytes) with the given
    /// op, xid, and yiaddr. Callers append options after the 240
    /// bytes if they want a full packet.
    fn build_header(op: u8, xid_be: [u8; 4], yiaddr: [u8; 4]) -> [u8; 240] {
        let mut hdr = [0u8; 240];
        hdr[0] = op;
        hdr[4..8].copy_from_slice(&xid_be);
        hdr[16..20].copy_from_slice(&yiaddr);
        hdr[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        hdr
    }

    #[test]
    fn accepts_wellformed_bootreply() {
        let xid = [0x12, 0x34, 0x56, 0x78];
        let hdr = build_header(OP_BOOTREPLY, xid, [10, 20, 30, 10]);
        assert_eq!(validate_header(&hdr, xid), Some([10, 20, 30, 10]));
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(validate_header(&[], [0; 4]), None);
        assert_eq!(validate_header(&[0xaa; 239], [0; 4]), None);
    }

    #[test]
    fn rejects_bootrequest_op() {
        let xid = [0; 4];
        let mut hdr = build_header(OP_BOOTREPLY, xid, [0; 4]);
        hdr[0] = 1; // BOOTREQUEST — our own frame echoed back
        assert_eq!(validate_header(&hdr, xid), None);
    }

    #[test]
    fn rejects_wrong_xid() {
        let xid = [0x12, 0x34, 0x56, 0x78];
        let hdr = build_header(OP_BOOTREPLY, xid, [0; 4]);
        let other_xid = [0xff, 0xff, 0xff, 0xff];
        assert_eq!(validate_header(&hdr, other_xid), None);
    }

    #[test]
    fn rejects_bad_magic_cookie() {
        let xid = [0; 4];
        let mut hdr = build_header(OP_BOOTREPLY, xid, [0; 4]);
        hdr[236] = 0x00; // clobber cookie
        assert_eq!(validate_header(&hdr, xid), None);
    }
}
