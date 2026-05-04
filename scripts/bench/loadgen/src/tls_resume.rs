// TLS 1.3 session-resumption throughput workload.
//
// Counterpart to `tls_handshake_max`. The two workloads measure
// opposite sides of the same path:
//
//   tls_handshake_max:  full ECDHE + ECDSA P-256 sign every conn.
//   tls_resume_max:     PSK-DHE binder verify, server skips the
//                       Certificate + CertificateVerify flight.
//
// Wire flow per worker:
//   1. First connection: fresh handshake. Server issues a ticket
//      via NewSessionTicket; rustls's in-memory session cache
//      stashes it under the SNI name.
//   2. Every subsequent connection on the same `ClientConfig`:
//      ClientHello includes pre_shared_key + psk_key_exchange_modes;
//      our server matches the ticket, verifies the binder, sends
//      a ServerHello with the matching `selected_identity`, skips
//      Cert + CertVerify, and finishes the handshake.
//
// Each worker keeps its own ClientConfig (= its own ticket cache)
// so the `first iteration is fresh` property holds per worker. We
// drop both (a) the global `warmup` window AND (b) every worker's
// first handshake from the histogram, so the recorded samples are
// the resumption hot path only.
//
// Resumption depends on a non-obvious rustls 0.23.x quirk: see the
// `SESSION_CACHE_CAPACITY` constant for why it must be ≥ 9. Booby-
// trap is silent — too small and every handshake stays fresh.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::WorkloadResult;

const PER_OP_TIMEOUT: Duration = Duration::from_secs(5);

/// Capacity of each worker's in-memory ticket cache.
///
/// Must be ≥ 9. rustls 0.23.x's `in_memory_sessions(N)` computes
/// `max_servers = ceil(N / MAX_TLS13_TICKETS_PER_SERVER)` where
/// MAX_TLS13_TICKETS_PER_SERVER = 8. With N ≤ 8 the result is 1,
/// and the LimitedCache's preemptive-eviction step
/// (`oldest.capacity() == oldest.len()` after push) immediately
/// evicts every just-inserted entry — silently breaking
/// resumption. Verified empirically: N=8 → kx_hint round-trip
/// returns None, N=9+ works. We use 64 to leave headroom and
/// match the rustls default-ish "many sessions" intent.
const SESSION_CACHE_CAPACITY: usize = 64;

#[derive(Debug)]
struct NoCertVerify;

impl rustls::client::danger::ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PKCS1_SHA256,
        ]
    }
}

/// Build a fresh ClientConfig with TLS 1.3 session resumption
/// explicitly enabled (in-memory ticket cache, per-worker).
fn build_client_config_with_resumption() -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    // The default `Resumption` already has an in-memory cache, but
    // setting it explicitly documents the intent and protects the
    // workload from a future rustls default change.
    cfg.resumption = Resumption::in_memory_sessions(SESSION_CACHE_CAPACITY);
    Arc::new(cfg)
}

pub async fn run(
    host: &str,
    port: u16,
    endpoint: &str,
    duration: Duration,
    warmup: Duration,
    parallelism: usize,
) -> WorkloadResult {
    let request = format!(
        "GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    );
    let request: Arc<[u8]> = Arc::from(request.into_bytes().into_boxed_slice());
    let host: Arc<str> = Arc::from(host.to_string().into_boxed_str());
    let server_name: ServerName<'static> = ServerName::try_from("localhost").unwrap();

    let total_window = duration + warmup;
    let warmup_end_marker = warmup;

    let start = Instant::now();
    let measure_start = start + warmup_end_marker;
    let deadline = start + total_window;

    let mut handles = Vec::with_capacity(parallelism);
    for _ in 0..parallelism {
        // Per-worker config = per-worker ticket cache. The first
        // handshake on each cache is necessarily fresh (no cached
        // ticket); we exclude it from the histogram below.
        let cfg = build_client_config_with_resumption();
        let connector = TlsConnector::from(cfg);
        let server_name = server_name.clone();
        let request = Arc::clone(&request);
        let host = Arc::clone(&host);
        let h = tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
            let mut count_post = 0u64;
            let mut buf = vec![0u8; 4096];
            // Tracks whether this worker has completed its seeding
            // fresh handshake. Once true, every subsequent successful
            // handshake is the resumption hot path.
            let mut seen_first = false;
            while Instant::now() < deadline {
                let t0 = Instant::now();
                let post_warmup = t0 >= measure_start;
                let ok = do_one_handshake(
                    &connector,
                    &server_name,
                    &host,
                    port,
                    &request,
                    &mut buf,
                )
                .await;
                if !ok {
                    continue;
                }
                if !seen_first {
                    seen_first = true;
                    continue;
                }
                if post_warmup {
                    let elapsed_us = t0.elapsed().as_micros() as u64;
                    let _ = hist.record(elapsed_us.max(1));
                    count_post += 1;
                }
            }
            (count_post, hist)
        });
        handles.push(h);
    }

    let mut total = 0u64;
    let mut combined = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
    for h in handles {
        if let Ok((c, h)) = h.await {
            total += c;
            combined.add(h).ok();
        }
    }

    let elapsed = duration;
    let p50 = combined.value_at_quantile(0.50);
    let p99 = combined.value_at_quantile(0.99);
    WorkloadResult { ops: total, elapsed, p50_us: p50, p99_us: p99 }
}

async fn do_one_handshake(
    connector: &TlsConnector,
    server_name: &ServerName<'static>,
    host: &str,
    port: u16,
    request: &[u8],
    buf: &mut [u8],
) -> bool {
    let tcp = match timeout(PER_OP_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    let _ = tcp.set_nodelay(true);
    // SO_LINGER={1,0}: send RST on close so the local side skips
    // TIME_WAIT entirely. macOS's 16K ephemeral pool exhausts in
    // <10s otherwise.
    let _ = tcp.set_zero_linger();

    let mut tls = match timeout(PER_OP_TIMEOUT, connector.connect(server_name.clone(), tcp)).await {
        Ok(Ok(t)) => t,
        _ => return false,
    };

    if timeout(PER_OP_TIMEOUT, tls.write_all(request)).await
        .ok().and_then(|r| r.ok()).is_none()
    {
        return false;
    }
    let drain = async {
        loop {
            match tls.read(buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    };
    let _ = timeout(PER_OP_TIMEOUT, drain).await;
    let _ = timeout(PER_OP_TIMEOUT, tls.shutdown()).await;
    true
}
