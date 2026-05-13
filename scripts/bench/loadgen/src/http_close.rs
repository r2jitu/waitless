// Plain-HTTP fresh-TCP-per-request workload.
//
// Mirrors `tls_handshake` but skips TLS — each iteration:
//   TCP connect → send GET with Connection: close → read until EOF → close.
//
// Use case: measures the server-side per-accept path end-to-end
// (3WHS, conn-state slot alloc, accept-loop body) without crypto
// overhead. The right workload for exposing conn-Future Box
// allocation pressure or any other accept-rate-bound work. Pairs
// with `tls_handshake` (same shape, +crypto) to isolate the crypto
// share of HTTPS handshake throughput.
//
// SO_LINGER={1,0} so close() sends RST instead of FIN — the
// client side skips TIME_WAIT, which would otherwise exhaust the
// macOS host's 16K ephemeral port pool within seconds at the
// rates this workload sustains.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::WorkloadResult;

const PER_OP_TIMEOUT: Duration = Duration::from_secs(5);

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

    let total_window = duration + warmup;
    let start = Instant::now();
    let measure_start = start + warmup;
    let deadline = start + total_window;

    let mut handles = Vec::with_capacity(parallelism);
    for _ in 0..parallelism {
        let request = Arc::clone(&request);
        let host = Arc::clone(&host);
        let h = tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
            let mut count_post = 0u64;
            let mut buf = vec![0u8; 4096];
            while Instant::now() < deadline {
                let t0 = Instant::now();
                let post_warmup = t0 >= measure_start;
                if !do_one_request(&host, port, &request, &mut buf).await {
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

    let p50 = combined.value_at_quantile(0.50);
    let p99 = combined.value_at_quantile(0.99);
    WorkloadResult {
        ops: total,
        elapsed: duration,
        p50_us: p50,
        p99_us: p99,
    }
}

async fn do_one_request(
    host: &str,
    port: u16,
    request: &[u8],
    buf: &mut [u8],
) -> bool {
    let mut tcp = match timeout(PER_OP_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    let _ = tcp.set_nodelay(true);
    // SO_LINGER={1,0}: close() emits RST instead of FIN — skip
    // TIME_WAIT on the client side. macOS's 16K ephemeral pool
    // exhausts in <1s at high rates without this.
    let _ = tcp.set_zero_linger();

    if timeout(PER_OP_TIMEOUT, tcp.write_all(request)).await
        .ok().and_then(|r| r.ok()).is_none()
    {
        return false;
    }
    // Drain until EOF — server closes after the response
    // (Connection: close).
    let drain = async {
        loop {
            match tcp.read(buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    };
    let _ = timeout(PER_OP_TIMEOUT, drain).await;
    let _ = timeout(PER_OP_TIMEOUT, tcp.shutdown()).await;
    true
}
