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
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::WorkloadResult;
use crate::tls_util::tcp_tls_config;

const PER_OP_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run(
    host: &str,
    port: u16,
    endpoint: &str,
    duration: Duration,
    warmup: Duration,
    parallelism: usize,
) -> WorkloadResult {
    // Resumption disabled: this workload measures FRESH handshake
    // throughput. With the server issuing NewSessionTicket on every
    // handshake, rustls's default in-memory cache would silently turn
    // subsequent handshakes into resumed PSK-DHE flights, biasing the
    // result low. The resumption hot path lives in `tls_resume.rs`.
    let cfg = tcp_tls_config(&[], Resumption::disabled());
    let connector = TlsConnector::from(cfg);
    // Server name verification is bypassed by `NoCertVerify`, so any
    // valid SNI string works — using a literal SNI that the dev cert
    // doesn't actually validate against is fine here.
    let server_name: ServerName<'static> = ServerName::try_from("localhost").unwrap();

    let request = format!("GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",);
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
                if !do_one_handshake(&connector, &server_name, &host, port, &request, &mut buf)
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
    WorkloadResult {
        ops: total,
        elapsed,
        p50_us: p50,
        p99_us: p99,
    }
}

async fn do_one_handshake(
    connector: &TlsConnector,
    server_name: &ServerName<'static>,
    host: &str,
    port: u16,
    request: &[u8],
    buf: &mut [u8],
) -> bool {
    // Per-op timeouts: at very high concurrent handshake rates the
    // server can momentarily drop a SYN or stall a handshake mid-
    // flight. Without a bound the worker would block forever and
    // its share of the deadline would be wasted, biasing the
    // aggregate down to zero. A 5s ceiling is well past any healthy
    // handshake (<50ms typical) but short enough to recover the
    // remainder of the bench window.
    let tcp = match timeout(PER_OP_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    let _ = tcp.set_nodelay(true);
    // SO_LINGER={1,0} → close() sends RST instead of FIN, so the
    // local side skips TIME_WAIT entirely. macOS's 16K ephemeral
    // pool exhausts in <10s at 2K hs/s × N workers without this.
    let _ = tcp.set_zero_linger();

    let mut tls = match timeout(PER_OP_TIMEOUT, connector.connect(server_name.clone(), tcp)).await {
        Ok(Ok(t)) => t,
        _ => return false,
    };

    if timeout(PER_OP_TIMEOUT, tls.write_all(request))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_none()
    {
        return false;
    }
    // Read until EOF or one full response — server closes after
    // serving (Connection: close). One outer timeout covers the
    // whole drain loop.
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
