// net/tls_server_trace.rs — Compile-time-gated handshake tracing.
//
// Enable with `--cfg=tls_debug` in rustc_flags on //uni-tls when
// you need to diagnose a broken handshake. When disabled (the default),
// every function here is a no-op stub with no arguments read — the
// compiler optimizes them to nothing, so there's zero runtime cost and
// zero code-size overhead in the release binary.
//
// The corresponding debug fields in `handshake::ClientHello` (e.g.
// `observed_key_shares`) are populated unconditionally by the parser —
// they're tiny (<200 bytes of stack data per ClientHello) and the cost
// is negligible given the parser only runs once per connection, so
// it's not worth the conditional-compilation complexity to gate them.

#![allow(unused_variables, dead_code)]

use super::{handshake, State, HandshakeError};

// `serial::puts` sink. Only compiled when `--cfg=tls_debug`
// is set in `//uni-tls`'s rustc_flags. On the
// bare-metal unikernel target we forward to the kernel's
// debug UART via `uni_kernel::serial::puts`; on hosted native
// builds we use libc `write(2, ...)` to stderr so the same
// debug flow works against the POSIX webserver. When
// `tls_debug` is off (the default), this whole module
// compiles to nothing.
#[cfg(all(tls_debug, target_os = "none"))]
use uni_kernel::serial;
#[cfg(all(tls_debug, not(target_os = "none")))]
mod serial {
    extern "C" {
        fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    }
    pub fn puts(bytes: &[u8]) {
        unsafe { let _ = write(2, bytes.as_ptr(), bytes.len()); }
    }
}

#[cfg(tls_debug)]
pub fn client_hello(ch: &handshake::ClientHello<'_>) {
    serial::puts(b"[tls-debug] ClientHello key_shares: ");
    if ch.observed_key_share_count == 0 {
        serial::puts(b"(none)");
    } else {
        for i in 0..ch.observed_key_share_count as usize {
            let (group, key_len) = ch.observed_key_shares[i];
            if i > 0 {
                serial::puts(b", ");
            }
            serial::puts(b"group=0x");
            put_u16_hex(group);
            serial::puts(b"(");
            put_group_name(group);
            serial::puts(b") len=");
            put_u16_dec(key_len);
        }
    }
    serial::puts(b"\n[tls-debug] ClientHello supported_groups: ");
    if ch.observed_supported_group_count == 0 {
        serial::puts(b"(none)");
    } else {
        for i in 0..ch.observed_supported_group_count as usize {
            let g = ch.observed_supported_groups[i];
            if i > 0 {
                serial::puts(b", ");
            }
            serial::puts(b"0x");
            put_u16_hex(g);
            serial::puts(b"(");
            put_group_name(g);
            serial::puts(b")");
        }
    }
    serial::puts(b"\n[tls-debug] ClientHello signature_algorithms: ");
    if ch.observed_sig_alg_count == 0 {
        serial::puts(b"(none)");
    } else {
        let mut offers_p256 = false;
        for i in 0..ch.observed_sig_alg_count as usize {
            let a = ch.observed_sig_algs[i];
            if a == 0x0403 {
                offers_p256 = true;
            }
            if i > 0 {
                serial::puts(b", ");
            }
            serial::puts(b"0x");
            put_u16_hex(a);
            serial::puts(b"(");
            put_sig_alg_name(a);
            serial::puts(b")");
        }
        serial::puts(b"\n[tls-debug] offers_ecdsa_p256=");
        serial::puts(if offers_p256 { b"true" } else { b"false" });
    }
    serial::puts(b"\n[tls-debug] has_x25519_share=");
    serial::puts(if ch.x25519_client_pub.is_some() {
        b"true"
    } else {
        b"false"
    });
    serial::puts(b" offers_x25519=");
    serial::puts(if ch.offers_x25519 { b"true" } else { b"false" });
    serial::puts(b"\n[tls-debug] psk=");
    if let Some(psk) = ch.psk.as_ref() {
        serial::puts(b"Some(identities=");
        put_u16_dec(psk.identity_count as u16);
        serial::puts(b" binders=");
        put_u16_dec(psk.binder_count as u16);
        serial::puts(b") ke_modes=0x");
        put_u16_hex(ch.psk_ke_modes as u16);
    } else {
        serial::puts(b"None ke_modes=0x");
        put_u16_hex(ch.psk_ke_modes as u16);
    }
    serial::puts(b"\n");
}
#[cfg(not(tls_debug))]
pub fn client_hello(_ch: &handshake::ClientHello<'_>) {}

#[cfg(tls_debug)]
pub fn step(msg: &[u8]) {
    serial::puts(msg);
}
#[cfg(not(tls_debug))]
pub fn step(_msg: &[u8]) {}

/// Dump `bytes` as a hex string prefixed with `label`. Wraps
/// every 32 bytes for readability. Used to compare server
/// flight contents across platforms when debugging handshake
/// correctness bugs.
#[cfg(tls_debug)]
pub fn hex_dump(label: &[u8], bytes: &[u8]) {
    serial::puts(b"[tls] ");
    serial::puts(label);
    serial::puts(b" (");
    put_u16_dec(bytes.len() as u16);
    serial::puts(b" bytes):\n");
    const HEX: &[u8] = b"0123456789abcdef";
    let mut buf = [0u8; 3];
    buf[2] = b' ';
    for (i, &b) in bytes.iter().enumerate() {
        buf[0] = HEX[(b >> 4) as usize];
        buf[1] = HEX[(b & 0xf) as usize];
        serial::puts(&buf);
        if (i + 1) % 32 == 0 {
            serial::puts(b"\n");
        }
    }
    if bytes.len() % 32 != 0 {
        serial::puts(b"\n");
    }
}
#[cfg(not(tls_debug))]
pub fn hex_dump(_label: &[u8], _bytes: &[u8]) {}

#[cfg(tls_debug)]
pub fn do_client_finished_entry(rx_len: usize, first_byte: Option<u8>) {
    serial::puts(b"[tls] do_client_finished entered, rx_len=");
    put_u16_dec(rx_len as u16);
    serial::puts(b"\n");
    if let Some(b) = first_byte {
        serial::puts(b"[tls]   first byte (content_type) = 0x");
        put_u16_hex(b as u16);
        serial::puts(b"\n");
    }
}
#[cfg(not(tls_debug))]
pub fn do_client_finished_entry(_rx_len: usize, _first_byte: Option<u8>) {}

#[cfg(tls_debug)]
pub fn waiting_for_bytes(have: usize, need: usize) {
    serial::puts(b"[tls]   waiting for more bytes (have ");
    put_u16_dec(have as u16);
    serial::puts(b", need ");
    put_u16_dec(need as u16);
    serial::puts(b")\n");
}
#[cfg(not(tls_debug))]
pub fn waiting_for_bytes(_have: usize, _need: usize) {}

#[cfg(tls_debug)]
pub fn record_header(content_type: u8, total_len: usize) {
    serial::puts(b"[tls]   full record arrived, content_type=0x");
    put_u16_hex(content_type as u16);
    serial::puts(b" len=");
    put_u16_dec(total_len as u16);
    serial::puts(b"\n");
}
#[cfg(not(tls_debug))]
pub fn record_header(_content_type: u8, _total_len: usize) {}

#[cfg(tls_debug)]
pub fn decrypted_record(inner_type: u8, pt_len: usize) {
    serial::puts(b"[tls]   decrypted, inner_type=0x");
    put_u16_hex(inner_type as u16);
    serial::puts(b" pt_len=");
    put_u16_dec(pt_len as u16);
    serial::puts(b"\n");
}
#[cfg(not(tls_debug))]
pub fn decrypted_record(_inner_type: u8, _pt_len: usize) {}

#[cfg(tls_debug)]
pub fn alert_received(level: u8, desc: u8) {
    serial::puts(b"[tls]   client sent ALERT level=");
    put_u16_dec(level as u16);
    serial::puts(b" desc=");
    put_u16_dec(desc as u16);
    serial::puts(b" (");
    serial::puts(alert_name(desc));
    serial::puts(b")\n");
}
#[cfg(not(tls_debug))]
pub fn alert_received(_level: u8, _desc: u8) {}

#[cfg(tls_debug)]
pub fn error(state: State, err: &HandshakeError) {
    serial::puts(b"[tls] ERROR in state=");
    serial::puts(state_name(state));
    serial::puts(b" err=");
    serial::puts(err_name(err));
    serial::puts(b"\n");
}
#[cfg(not(tls_debug))]
pub fn error(_state: State, _err: &HandshakeError) {}

// ── Internal formatting helpers (compiled only with tls_debug) ──────
#[cfg(tls_debug)]
fn put_u16_hex(v: u16) {
    let hex = b"0123456789abcdef";
    let buf = [
        hex[((v >> 12) & 0xf) as usize],
        hex[((v >> 8) & 0xf) as usize],
        hex[((v >> 4) & 0xf) as usize],
        hex[(v & 0xf) as usize],
    ];
    serial::puts(&buf);
}

#[cfg(tls_debug)]
fn put_u16_dec(mut v: u16) {
    if v == 0 {
        serial::puts(b"0");
        return;
    }
    let mut buf = [0u8; 6];
    let mut n = 0;
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut out = [0u8; 6];
    for i in 0..n {
        out[i] = buf[n - 1 - i];
    }
    serial::puts(&out[..n]);
}

#[cfg(tls_debug)]
fn put_group_name(g: u16) {
    let name: &[u8] = match g {
        0x0017 => b"secp256r1",
        0x0018 => b"secp384r1",
        0x0019 => b"secp521r1",
        0x001d => b"x25519",
        0x001e => b"x448",
        0x0100 => b"ffdhe2048",
        0x0101 => b"ffdhe3072",
        0x11ec => b"x25519mlkem768",
        0x6399 => b"x25519kyber768draft00",
        _ => b"?",
    };
    serial::puts(name);
}

#[cfg(tls_debug)]
fn put_sig_alg_name(a: u16) {
    let name: &[u8] = match a {
        0x0201 => b"rsa_pkcs1_sha1",
        0x0203 => b"ecdsa_sha1",
        0x0401 => b"rsa_pkcs1_sha256",
        0x0403 => b"ecdsa_secp256r1_sha256",
        0x0501 => b"rsa_pkcs1_sha384",
        0x0503 => b"ecdsa_secp384r1_sha384",
        0x0601 => b"rsa_pkcs1_sha512",
        0x0603 => b"ecdsa_secp521r1_sha512",
        0x0804 => b"rsa_pss_rsae_sha256",
        0x0805 => b"rsa_pss_rsae_sha384",
        0x0806 => b"rsa_pss_rsae_sha512",
        0x0807 => b"ed25519",
        0x0808 => b"ed448",
        0x0809 => b"rsa_pss_pss_sha256",
        0x080a => b"rsa_pss_pss_sha384",
        0x080b => b"rsa_pss_pss_sha512",
        _ => b"?",
    };
    serial::puts(name);
}

#[cfg(tls_debug)]
fn state_name(s: State) -> &'static [u8] {
    match s {
        State::WaitClientHello => b"WaitClientHello",
        State::WaitClientFinished => b"WaitClientFinished",
        State::Established => b"Established",
        State::Closed => b"Closed",
        State::Failed => b"Failed",
    }
}

#[cfg(tls_debug)]
fn err_name(e: &HandshakeError) -> &'static [u8] {
    match e {
        HandshakeError::ParseError(_) => b"ParseError",
        HandshakeError::RecordError(_) => b"RecordError",
        HandshakeError::UnsupportedClient => b"UnsupportedClient",
        HandshakeError::AeadFailed => b"AeadFailed",
        HandshakeError::TxBufTooSmall => b"TxBufTooSmall",
        HandshakeError::BadClientFinished => b"BadClientFinished",
        HandshakeError::UnexpectedRecord => b"UnexpectedRecord",
        HandshakeError::Internal => b"Internal",
    }
}

#[cfg(tls_debug)]
fn alert_name(desc: u8) -> &'static [u8] {
    match desc {
        0 => b"close_notify",
        10 => b"unexpected_message",
        20 => b"bad_record_mac",
        22 => b"record_overflow",
        40 => b"handshake_failure",
        42 => b"bad_certificate",
        43 => b"unsupported_certificate",
        44 => b"certificate_revoked",
        45 => b"certificate_expired",
        46 => b"certificate_unknown",
        47 => b"illegal_parameter",
        48 => b"unknown_ca",
        49 => b"access_denied",
        50 => b"decode_error",
        51 => b"decrypt_error",
        70 => b"protocol_version",
        71 => b"insufficient_security",
        80 => b"internal_error",
        86 => b"inappropriate_fallback",
        90 => b"user_canceled",
        109 => b"missing_extension",
        110 => b"unsupported_extension",
        112 => b"unrecognized_name",
        113 => b"bad_certificate_status_response",
        115 => b"unknown_psk_identity",
        116 => b"certificate_required",
        120 => b"no_application_protocol",
        _ => b"?",
    }
}
