// SOCKS5 wire parsing (RFC 1928) — the pure, transport-free core.
//
// Everything here is a function over byte slices: no I/O, no waitless
// runtime, no allocation. That keeps the protocol logic unit-testable
// on the host (`bazel test //apps/socks:socks5_test`) while `main.rs`
// owns the async reads/writes that feed these parsers. The split is
// deliberate teaching structure: the *what* (byte layout, validity,
// the exact reply codes) lives here and is exercised by tests; the
// *how* (await a read, relay, time out) lives next door in main.rs.
//
// We implement only what an IPv4 CONNECT proxy needs. Domain (ATYP
// 0x03) and IPv6 (ATYP 0x04) targets are recognised and rejected with
// the correct reply code rather than mis-parsed — see `RequestError`.

// `#![no_std]` for the unikernel build; the test build links libstd so
// `#[test]` and the test harness are available. The module body itself
// uses neither — it is pure `core`.
#![cfg_attr(not(test), no_std)]

/// SOCKS protocol version byte. We speak 5 only.
pub const VER: u8 = 0x05;

/// CONNECT command — the only one this proxy implements. BIND (0x02)
/// and UDP ASSOCIATE (0x03) are valid SOCKS5 commands we don't offer.
pub const CMD_CONNECT: u8 = 0x01;

/// Address types (the request's ATYP field).
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// "No authentication required" — the single method we advertise in
/// the method-selection reply. SOCKS5 auth (username/password, GSSAPI)
/// is out of scope for an example proxy.
pub const METHOD_NO_AUTH: u8 = 0x00;
/// Sentinel a server sends when it accepts none of the client's
/// offered methods. We never need it (we always accept no-auth), but
/// it documents the field.
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xff;

/// Reply codes (REP field of the server's CONNECT reply). Names match
/// RFC 1928 §6. We use a subset; the rest are listed for the reader.
pub mod rep {
    pub const SUCCEEDED: u8 = 0x00;
    pub const GENERAL_FAILURE: u8 = 0x01;
    #[allow(dead_code)]
    pub const NOT_ALLOWED: u8 = 0x02;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    #[allow(dead_code)]
    pub const TTL_EXPIRED: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// The fixed 10-byte CONNECT reply this proxy sends for every outcome:
/// `VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0`. RFC 1928 lets
/// the server report the bound address it used on the target side; a
/// transparent relay has nothing useful to advertise there, and every
/// real SOCKS5 client (curl, browsers, ssh -D) ignores BND for
/// CONNECT, so we always send the all-zero IPv4 form. `rep` is the
/// only byte that varies — success vs the specific failure code.
pub fn connect_reply(rep: u8) -> [u8; 10] {
    [VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// Why the greeting was rejected. The greeting carries no reply code
/// of its own — a bad version means we just close — so this maps to
/// "close the connection" at the call site.
#[derive(Debug, PartialEq, Eq)]
pub enum GreetingError {
    /// First byte was not 0x05. Not a SOCKS5 client (or garbage).
    BadVersion,
    /// NMETHODS was 0 — a malformed greeting (a client must offer at
    /// least one method).
    NoMethods,
}

/// Parse the SOCKS5 greeting `VER NMETHODS METHODS[NMETHODS]`.
///
/// `buf` must be exactly the `NMETHODS` methods bytes preceded by the
/// two-byte header — i.e. the caller has already read `2 + nmethods`
/// bytes (it learns `nmethods` from byte 1, then reads that many
/// more). We re-validate the length here so a caller bug can't walk
/// off the end. Returns the chosen method on success.
///
/// We accept no-auth unconditionally: if the client's method list does
/// not even contain 0x00 we still reply 0x00, because every SOCKS5
/// client that bothers to connect to an open proxy offers it, and a
/// stricter check buys nothing for an example. The return value is the
/// method to put in the selection reply.
pub fn parse_greeting(buf: &[u8]) -> Result<u8, GreetingError> {
    // Need at least VER + NMETHODS.
    let &[ver, nmethods, ..] = buf else {
        return Err(GreetingError::BadVersion);
    };
    if ver != VER {
        return Err(GreetingError::BadVersion);
    }
    if nmethods == 0 {
        return Err(GreetingError::NoMethods);
    }
    // The header claims `nmethods` method bytes follow; reject a buffer
    // that doesn't actually carry them (defends the caller's read).
    if buf.len() != 2 + nmethods as usize {
        return Err(GreetingError::NoMethods);
    }
    Ok(METHOD_NO_AUTH)
}

/// The destination a CONNECT request named. IPv4 only — a domain or
/// IPv6 target never reaches this type; it surfaces as the matching
/// `RequestError` instead.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Target {
    /// Destination address octets, big-endian network order (as on the
    /// wire). `[a, b, c, d]` == `a.b.c.d`.
    pub ip: [u8; 4],
    /// Destination port, host order (already byte-swapped from the
    /// wire's big-endian DST.PORT).
    pub port: u16,
}

/// Why a request could not be honoured, paired with the reply code to
/// send back before closing. The caller writes `connect_reply(err.rep())`
/// and drops the connection.
#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    /// VER byte was not 0x05, or the buffer was too short to be a
    /// request header. No meaningful reply — close.
    Malformed,
    /// CMD was not CONNECT (BIND / UDP ASSOCIATE / garbage).
    CommandNotSupported,
    /// ATYP was domain (0x03) or IPv6 (0x04). We can't resolve a
    /// hostname (no DNS resolver is built — see main.rs) and don't
    /// route IPv6, so both are address-type-not-supported.
    AddressTypeNotSupported,
}

impl RequestError {
    /// The SOCKS5 reply code that communicates this failure to the
    /// client. `Malformed` has no good code; we use general-failure,
    /// though in practice the caller closes without replying.
    pub fn rep(&self) -> u8 {
        match self {
            RequestError::Malformed => rep::GENERAL_FAILURE,
            RequestError::CommandNotSupported => rep::COMMAND_NOT_SUPPORTED,
            RequestError::AddressTypeNotSupported => rep::ADDRESS_TYPE_NOT_SUPPORTED,
        }
    }
}

/// Parse a SOCKS5 CONNECT request header up to and including ATYP, then
/// the IPv4 address + port.
///
/// Wire layout (RFC 1928 §4):
/// `VER CMD RSV ATYP DST.ADDR DST.PORT`. For ATYP=IPv4 that is exactly
/// 10 bytes: `05 01 00 01 a b c d p0 p1`. `buf` must be the whole
/// request as read so far; we validate the length for the IPv4 case.
///
/// CMD/ATYP are checked in the order a client would care about: a
/// non-CONNECT command is reported even for a domain target, matching
/// how real proxies answer. A domain or IPv6 ATYP returns
/// `AddressTypeNotSupported` *without* needing the (variable-length)
/// address bytes — we reject on the type alone.
pub fn parse_request(buf: &[u8]) -> Result<Target, RequestError> {
    // VER CMD RSV ATYP — the fixed 4-byte prefix.
    let &[ver, cmd, _rsv, atyp, ..] = buf else {
        return Err(RequestError::Malformed);
    };
    if ver != VER {
        return Err(RequestError::Malformed);
    }
    if cmd != CMD_CONNECT {
        return Err(RequestError::CommandNotSupported);
    }
    match atyp {
        ATYP_IPV4 => {}
        ATYP_DOMAIN | ATYP_IPV6 => return Err(RequestError::AddressTypeNotSupported),
        // Unknown ATYP — treat as unsupported too (not malformed: the
        // header was well-formed, the address family just isn't ours).
        _ => return Err(RequestError::AddressTypeNotSupported),
    }
    // IPv4: 4 addr bytes + 2 port bytes after the 4-byte prefix.
    let &[_, _, _, _, a, b, c, d, p0, p1] = buf else {
        return Err(RequestError::Malformed);
    };
    Ok(Target {
        ip: [a, b, c, d],
        port: u16::from_be_bytes([p0, p1]),
    })
}

// ---- Host unit tests --------------------------------------------------------
//
// Run on the host (libstd) via `bazel test //apps/socks:socks5_test`.
// They pin the byte layout and every error path of the two parsers so a
// refactor of main.rs's read loop can't silently change the protocol.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_no_auth_single_method() {
        // VER=5, NMETHODS=1, METHODS=[0x00 no-auth].
        assert_eq!(parse_greeting(&[0x05, 0x01, 0x00]), Ok(METHOD_NO_AUTH));
    }

    #[test]
    fn greeting_multiple_methods_ok() {
        // VER=5, NMETHODS=2, METHODS=[0x00, 0x02]. We accept no-auth.
        assert_eq!(parse_greeting(&[0x05, 0x02, 0x00, 0x02]), Ok(METHOD_NO_AUTH));
    }

    #[test]
    fn greeting_bad_version_rejected() {
        assert_eq!(parse_greeting(&[0x04, 0x01, 0x00]), Err(GreetingError::BadVersion));
    }

    #[test]
    fn greeting_too_short_rejected() {
        assert_eq!(parse_greeting(&[0x05]), Err(GreetingError::BadVersion));
    }

    #[test]
    fn greeting_zero_methods_rejected() {
        assert_eq!(parse_greeting(&[0x05, 0x00]), Err(GreetingError::NoMethods));
    }

    #[test]
    fn greeting_length_mismatch_rejected() {
        // Claims 3 methods but only 1 byte follows.
        assert_eq!(parse_greeting(&[0x05, 0x03, 0x00]), Err(GreetingError::NoMethods));
    }

    #[test]
    fn request_ipv4_connect_parsed() {
        // CONNECT 10.0.2.2:8080 → 05 01 00 01 0a 00 02 02 1f 90.
        let req = [0x05, 0x01, 0x00, 0x01, 10, 0, 2, 2, 0x1f, 0x90];
        assert_eq!(
            parse_request(&req),
            Ok(Target { ip: [10, 0, 2, 2], port: 8080 }),
        );
    }

    #[test]
    fn request_port_is_big_endian() {
        // Port 0x0050 = 80; ensure we don't byte-swap the wrong way.
        let req = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        assert_eq!(parse_request(&req).unwrap().port, 80);
    }

    #[test]
    fn request_non_connect_command() {
        // CMD=0x02 (BIND).
        let req = [0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80];
        assert_eq!(parse_request(&req), Err(RequestError::CommandNotSupported));
    }

    #[test]
    fn request_domain_atyp_unsupported() {
        // ATYP=0x03 (domain). Rejected on the type alone; we don't even
        // look at the (variable-length) name bytes.
        let req = [0x05, 0x01, 0x00, 0x03, 0x09, b'l', b'o', b'c'];
        assert_eq!(parse_request(&req), Err(RequestError::AddressTypeNotSupported));
    }

    #[test]
    fn request_ipv6_atyp_unsupported() {
        let req = [0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0];
        assert_eq!(parse_request(&req), Err(RequestError::AddressTypeNotSupported));
    }

    #[test]
    fn request_bad_version_malformed() {
        let req = [0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80];
        assert_eq!(parse_request(&req), Err(RequestError::Malformed));
    }

    #[test]
    fn request_short_ipv4_malformed() {
        // Header says IPv4 but only 8 bytes present (need 10).
        let req = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4];
        assert_eq!(parse_request(&req), Err(RequestError::Malformed));
    }

    #[test]
    fn request_truncated_header_malformed() {
        assert_eq!(parse_request(&[0x05, 0x01]), Err(RequestError::Malformed));
    }

    #[test]
    fn connect_reply_shape() {
        let r = connect_reply(rep::SUCCEEDED);
        assert_eq!(r, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        // Only REP varies across outcomes.
        assert_eq!(connect_reply(rep::CONNECTION_REFUSED)[1], 0x05);
    }
}
