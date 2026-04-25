// TLS 1.3 handshake throughput workload.
//
// `parallelism` worker tasks loop:
//   TCP connect → TLS handshake → send GET → read response → close.
//
// Each worker keeps its own latency histogram, dropping the first
// `warmup` window of samples, and at the end the main task
// merges them.
//
// Skip cert verification (the unikernel ships a self-signed dev
// cert; the workload measures handshake throughput, not chain
// validation).

use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::WorkloadResult;

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

fn build_client_config() -> Arc<ClientConfig> {
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
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
    let _ = RootCertStore::empty(); // touch import so unused-import lint stays quiet
    let cfg = build_client_config();
    let connector = TlsConnector::from(cfg);
    // Server name verification is bypassed by `NoCertVerify`, so any
    // valid SNI string works — using a literal SNI that the dev cert
    // doesn't actually validate against is fine here.
    let server_name: ServerName<'static> = ServerName::try_from("localhost").unwrap();

    let request = format!(
        "GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    );
    let request: Arc<[u8]> = Arc::from(request.into_bytes().into_boxed_slice());

    let host: Arc<str> = Arc::from(host.to_string().into_boxed_str());

    let total_window = duration + warmup;
    let warmup_end_marker = warmup;

    let start = Instant::now();
    let measure_start = start + warmup_end_marker;
    let deadline = start + total_window;

    let mut handles = Vec::with_capacity(parallelism);
    for _ in 0..parallelism {
        let connector = connector.clone();
        let server_name = server_name.clone();
        let request = Arc::clone(&request);
        let host = Arc::clone(&host);
        let h = tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
            let mut count_post = 0u64;
            let mut buf = vec![0u8; 4096];
            while Instant::now() < deadline {
                let t0 = Instant::now();
                let post_warmup = t0 >= measure_start;
                if !do_one_handshake(
                    &connector,
                    &server_name,
                    &host,
                    port,
                    &request,
                    &mut buf,
                )
                .await
                {
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

    let elapsed = duration; // measurement window length
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
    let tcp = match TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    // The Python version used SO_LINGER=0 to skip TIME_WAIT —
    // tokio deprecated that on TcpStream and the comment is the
    // explanation: SO_LINGER blocks on drop, which is wrong for
    // an async runtime. Without it we'll exhaust the ephemeral
    // port range faster on long runs; for the bench durations we
    // care about (5-10s), the limit is high enough that it
    // doesn't bite. If it ever does, switch to a syscall-level
    // setsockopt with the FD pulled via TcpStream::as_raw_fd.
    let _ = tcp.set_nodelay(true);

    let mut tls = match connector.connect(server_name.clone(), tcp).await {
        Ok(t) => t,
        Err(_) => return false,
    };

    if tls.write_all(request).await.is_err() {
        return false;
    }
    // Read until EOF or one full response — server closes after
    // serving (Connection: close).
    loop {
        match tls.read(buf).await {
            Ok(0) => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    let _ = tls.shutdown().await;
    true
}
