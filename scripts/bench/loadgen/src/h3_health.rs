// HTTP/3 keep-alive throughput workload.
//
// `parallelism` worker tasks, each owning its own QUIC connection
// to the server. After the one-time handshake (skipped from the
// histogram), each worker fires sequential GET requests on the
// keep-alive connection and measures per-request latency. This is
// the QUIC analogue of `health_tls_max` (HTTPS/TLS keep-alive over
// TCP) — measures the AEAD + packet-encode + UDP-emit hot path
// that item B2 (encoder writes directly into the driver TX-pool
// slot) targets.
//
// Skip cert verification (the unikernel ships a self-signed dev
// cert; the workload measures throughput, not chain validation).

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use http::Request;
use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls::pki_types::ServerName;
use tokio::time::timeout;

use crate::WorkloadResult;

const PER_OP_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `f` only the first time the gate is `false`. Lets each
/// per-worker error path log once instead of once-per-iteration.
fn log_first<F: FnOnce(&mut bool)>(gate: &mut bool, f: F) {
    if !*gate {
        f(gate);
    }
}

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

fn build_client_config() -> ClientConfig {
    let mut tls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    // ALPN: the unikernel's QUIC server only accepts `h3` (RFC 9114).
    // Without this, the QUIC handshake completes but the H3 layer
    // refuses the connection with `H3_NO_ERROR`.
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
        .expect("valid QUIC TLS config");

    let mut cfg = ClientConfig::new(Arc::new(crypto));

    // Generous transport defaults — the workload measures
    // application-layer throughput, not flow-control behaviour, so
    // bump the per-stream and per-conn windows past the one-RTT
    // working set.
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(256u32.into())
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    cfg.transport_config(Arc::new(transport));

    cfg
}

fn resolve(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    // Match the loopback-on-numeric pattern the other workloads use:
    // `localhost` resolves to v6 first on some glibc configs, but
    // the unikernel listens on v4. Prefer the first v4 result.
    let target = (host, port);
    let mut addrs: Vec<_> = target.to_socket_addrs().ok()?.collect();
    addrs.sort_by_key(|a| match a {
        std::net::SocketAddr::V4(_) => 0,
        std::net::SocketAddr::V6(_) => 1,
    });
    addrs.into_iter().next()
}

pub async fn run(
    host: &str,
    port: u16,
    endpoint: &str,
    duration: Duration,
    warmup: Duration,
    parallelism: usize,
) -> WorkloadResult {
    let server_addr = match resolve(host, port) {
        Some(a) => a,
        None => {
            eprintln!("h3_health: failed to resolve {host}:{port}");
            return WorkloadResult {
                ops: 0,
                elapsed: duration,
                p50_us: 0,
                p99_us: 0,
            };
        }
    };

    let client_cfg = Arc::new(build_client_config());
    let endpoint = Arc::new(endpoint.to_string());
    let host: Arc<str> = Arc::from(host.to_string().into_boxed_str());

    let total_window = duration + warmup;
    let start = Instant::now();
    let measure_start = start + warmup;
    let deadline = start + total_window;

    let mut handles = Vec::with_capacity(parallelism);
    for worker_idx in 0..parallelism {
        let client_cfg = client_cfg.clone();
        let endpoint = endpoint.clone();
        let host = host.clone();
        let h = tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
            let mut count_post = 0u64;
            // First-occurrence log gates: a single stuck connection
            // would otherwise spam stderr with the same line every
            // few microseconds.
            let mut logged_send_err = false;
            let mut logged_send_timeout = false;
            let mut logged_recv_err = false;
            let mut logged_recv_timeout = false;

            // One QUIC endpoint (UDP socket) per worker so each
            // worker drives its own 4-tuple (the unikernel hashes
            // datagrams to per-core slot tables on the source-IP
            // + source-port pair).
            let bind: std::net::SocketAddr = match server_addr {
                std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let mut quinn_ep = match Endpoint::client(bind) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("h3_health[{worker_idx}]: bind failed: {e}");
                    return (count_post, hist);
                }
            };
            quinn_ep.set_default_client_config((*client_cfg).clone());

            // Server name for SNI. NoCertVerify accepts anything, so
            // any string works.
            let conn = match timeout(
                PER_OP_TIMEOUT,
                quinn_ep.connect(server_addr, "unikernel.local").unwrap(),
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    eprintln!("h3_health[{worker_idx}]: connect failed: {e}");
                    return (count_post, hist);
                }
                Err(_) => {
                    eprintln!("h3_health[{worker_idx}]: connect timed out");
                    return (count_post, hist);
                }
            };

            let h3_conn = h3_quinn::Connection::new(conn);
            let (mut driver, mut send_request) =
                match h3::client::new(h3_conn).await {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("h3_health[{worker_idx}]: h3 init failed: {e}");
                        return (count_post, hist);
                    }
                };

            // Drive the H3 connection background task. It pumps
            // QUIC events into the h3 state machine; without this
            // requests stall after the first.
            let driver_task = tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });

            while Instant::now() < deadline {
                let t0 = Instant::now();
                let post_warmup = t0 >= measure_start;

                let req = Request::builder()
                    .method("GET")
                    .uri(format!("https://{}{}", host, endpoint))
                    .body(())
                    .unwrap();

                // Per-op error handling: log once per failure mode
                // (not once per iteration) — a stuck connection
                // would otherwise spam stderr with thousands of
                // identical lines. The loadgen's stdout RPS / P50_US
                // / P99_US line is what the harness consumes; stderr
                // is for diagnostics only.
                let mut stream = match timeout(
                    PER_OP_TIMEOUT,
                    send_request.send_request(req),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        log_first(&mut logged_send_err, |once| {
                            eprintln!(
                                "h3_health[{worker_idx}]: send_request err (logged once): {e}"
                            );
                            *once = true;
                        });
                        continue;
                    }
                    Err(_) => {
                        log_first(&mut logged_send_timeout, |once| {
                            eprintln!(
                                "h3_health[{worker_idx}]: send_request timed out (logged once)"
                            );
                            *once = true;
                        });
                        continue;
                    }
                };
                if timeout(PER_OP_TIMEOUT, stream.finish()).await.is_err() {
                    continue;
                }
                match timeout(PER_OP_TIMEOUT, stream.recv_response()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        log_first(&mut logged_recv_err, |once| {
                            eprintln!(
                                "h3_health[{worker_idx}]: recv_response err (logged once): {e}"
                            );
                            *once = true;
                        });
                        continue;
                    }
                    Err(_) => {
                        log_first(&mut logged_recv_timeout, |once| {
                            eprintln!(
                                "h3_health[{worker_idx}]: recv_response timed out (logged once)"
                            );
                            *once = true;
                        });
                        continue;
                    }
                }
                loop {
                    match timeout(PER_OP_TIMEOUT, stream.recv_data()).await {
                        Ok(Ok(Some(_chunk))) => continue,
                        Ok(Ok(None)) => break,
                        _ => break,
                    }
                }

                if post_warmup {
                    let elapsed_us = t0.elapsed().as_micros() as u64;
                    let _ = hist.record(elapsed_us.max(1));
                    count_post += 1;
                }
            }

            // Tear down: dropping `send_request` lets the driver's
            // poll_close complete. Wait for the driver task so we
            // don't leak the endpoint's UDP socket beyond the
            // worker's lifetime.
            drop(send_request);
            let _ = driver_task.await;
            quinn_ep.close(0u32.into(), b"bye");
            quinn_ep.wait_idle().await;
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
    WorkloadResult {
        ops: total,
        elapsed,
        p50_us: p50,
        p99_us: p99,
    }
}
