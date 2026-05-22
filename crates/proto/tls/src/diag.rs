// tls/diag.rs — observability for the TLS 1.3 server.
//
// The observability doctrine (`docs/observability.md`) applied to
// TLS. The crate already had two telemetry surfaces — `profile.rs`
// (per-stage handshake timing) and `record.rs` (encrypt/decrypt
// throughput). The gap was the *failure pillar*: when a handshake
// failed, nothing retained which state it failed in or why.
//
// `Counters` plus `LAST_HANDSHAKE_FAILURE` close that. Surfaced as
// the `"tls"` block of `/obs` via `write_obs_json`. TLS builds on
// the host and the app links it directly, so — unlike the `net` /
// NIC crates — no `waitless_backend` seam is needed.

use core::fmt;

use obs::{Counter, LastEvent, ObsRecord};

use crate::server::{HandshakeError, State};

/// One counter per TLS handshake-lifecycle event.
pub struct Counters {
    /// Handshakes that reached `Established`.
    pub handshakes_completed: Counter,
    /// `advance()` returned `Err` — a handshake aborted. Read
    /// `LAST_HANDSHAKE_FAILURE` for the state + cause.
    pub handshake_failures: Counter,
    /// The `UnsupportedClient` subset of `handshake_failures` — a
    /// ClientHello lacking TLS 1.3 / X25519 / our cipher suite.
    pub client_hello_rejected: Counter,
    /// `close_notify` alerts emitted (RFC 8446 §6.1 clean close).
    pub close_notify_sent: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            handshakes_completed: Counter::new(),
            handshake_failures: Counter::new(),
            client_hello_rejected: Counter::new(),
            close_notify_sent: Counter::new(),
        }
    }
}

/// Process-wide TLS counters.
pub static COUNTERS: Counters = Counters::new();

/// Most recent aborted handshake — the state it failed in and why.
pub static LAST_HANDSHAKE_FAILURE: LastEvent<HandshakeFailRecord> = LastEvent::new();

/// Snapshot payload for `LAST_HANDSHAKE_FAILURE`.
#[derive(Clone, Copy)]
pub struct HandshakeFailRecord {
    /// Handshake state the failure occurred in.
    pub state: State,
    /// Cause — the `HandshakeError` kind as a stable token.
    pub error: &'static str,
    /// `tls::ticket::now_us()` at the failure.
    pub at_us: u64,
}

impl ObsRecord for HandshakeFailRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            w,
            "\"state\":\"{}\",\"error\":\"{}\",\"at_us\":{}",
            state_str(self.state),
            self.error,
            self.at_us,
        )
    }
}

/// Stable lowercase token for a handshake `State`.
fn state_str(s: State) -> &'static str {
    match s {
        State::WaitClientHello => "wait_client_hello",
        State::WaitClientFinished => "wait_client_finished",
        State::Established => "established",
        State::Closed => "closed",
        State::Failed => "failed",
    }
}

/// Stable lowercase token for a `HandshakeError` kind.
fn error_str(e: &HandshakeError) -> &'static str {
    match e {
        HandshakeError::ParseError(_) => "parse_error",
        HandshakeError::RecordError(_) => "record_error",
        HandshakeError::UnsupportedClient => "unsupported_client",
        HandshakeError::AeadFailed => "aead_failed",
        HandshakeError::TxBufTooSmall => "tx_buf_too_small",
        HandshakeError::BadClientFinished => "bad_client_finished",
        HandshakeError::UnexpectedRecord => "unexpected_record",
        HandshakeError::Internal => "internal",
    }
}

/// Record an aborted handshake: bump `handshake_failures` (and
/// `client_hello_rejected` for the `UnsupportedClient` subset) and
/// snapshot the state + cause into `LAST_HANDSHAKE_FAILURE`.
pub fn record_handshake_failure(state: State, err: &HandshakeError) {
    COUNTERS.handshake_failures.bump();
    if matches!(err, HandshakeError::UnsupportedClient) {
        COUNTERS.client_hello_rejected.bump();
    }
    LAST_HANDSHAKE_FAILURE.record(HandshakeFailRecord {
        state,
        error: error_str(err),
        at_us: crate::ticket::now_us(),
    });
}

/// Render the TLS observability block as a JSON object — the
/// handshake-lifecycle counters, the record-layer encrypt/decrypt
/// throughput (from `record::encrypt_stats`), then the
/// `LAST_HANDSHAKE_FAILURE` snapshot. This is TLS's `/obs` block.
pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
    let c = &COUNTERS;
    let (enc_b, enc_r, enc_cyc, dec_b, dec_r, dec_cyc) = crate::record::encrypt_stats();
    write!(
        w,
        "{{\"handshakes_completed\":{},\"handshake_failures\":{},\
         \"client_hello_rejected\":{},\"close_notify_sent\":{},\
         \"encrypt_bytes\":{},\"encrypt_records\":{},\"encrypt_cycles\":{},\
         \"decrypt_bytes\":{},\"decrypt_records\":{},\"decrypt_cycles\":{},",
        c.handshakes_completed.get(),
        c.handshake_failures.get(),
        c.client_hello_rejected.get(),
        c.close_notify_sent.get(),
        enc_b,
        enc_r,
        enc_cyc,
        dec_b,
        dec_r,
        dec_cyc,
    )?;
    LAST_HANDSHAKE_FAILURE.write_json(w, "last_handshake_failure")?;
    w.write_str("}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn handshake_fail_record_renders() {
        let mut s = String::new();
        HandshakeFailRecord {
            state: State::WaitClientFinished,
            error: "bad_client_finished",
            at_us: 5_000,
        }
        .write_fields(&mut s)
        .unwrap();
        assert_eq!(
            s,
            "\"state\":\"wait_client_finished\",\
             \"error\":\"bad_client_finished\",\"at_us\":5000"
        );
    }

    #[test]
    fn record_handshake_failure_bumps_counters() {
        let fails = COUNTERS.handshake_failures.get();
        let rejects = COUNTERS.client_hello_rejected.get();
        record_handshake_failure(State::WaitClientHello, &HandshakeError::UnsupportedClient);
        assert_eq!(COUNTERS.handshake_failures.get(), fails + 1);
        assert_eq!(COUNTERS.client_hello_rejected.get(), rejects + 1);
    }

    #[test]
    fn write_obs_json_is_one_object() {
        let mut s = String::new();
        write_obs_json(&mut s).unwrap();
        assert!(s.starts_with('{') && s.ends_with('}'));
        assert!(s.contains("\"handshakes_completed\":"));
        assert!(s.contains("\"last_handshake_failure\":{\"count\":"));
    }
}
