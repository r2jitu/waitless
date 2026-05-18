// TCP echo throughput workload.
//
// Opens `connections` TCP streams, sends a fixed-size payload on
// each in a tight loop, waits for the echoed response. Latency
// samples come from connection 0 only (cheap; representative).
// All connections share the same start barrier so per-conn ramp
// doesn't skew aggregate throughput.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Barrier;

use crate::WorkloadResult;

pub async fn run(
    host: &str,
    port: u16,
    duration: Duration,
    connections: usize,
    msg_size: usize,
) -> WorkloadResult {
    let msg: Arc<[u8]> = Arc::from(vec![b'p'; msg_size].into_boxed_slice());
    let host: Arc<str> = Arc::from(host.to_string().into_boxed_str());

    // Barrier: every connection establishes, then we release them
    // all at once and start the clock. +1 for the main task.
    let barrier = Arc::new(Barrier::new(connections + 1));

    let mut handles = Vec::with_capacity(connections);
    for i in 0..connections {
        let host = Arc::clone(&host);
        let msg = Arc::clone(&msg);
        let barrier = Arc::clone(&barrier);
        let sample_latency = i == 0;
        let h = tokio::spawn(async move {
            let mut sock = match TcpStream::connect((&*host, port)).await {
                Ok(s) => s,
                Err(_) => {
                    barrier.wait().await;
                    return (
                        0u64,
                        Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap(),
                    );
                }
            };
            let _ = sock.set_nodelay(true);
            // SO_LINGER={1,0} → close() RSTs instead of FIN, so we
            // skip TIME_WAIT on the loadgen's side. Otherwise N conns
            // × M back-to-back runs exhaust macOS's 16K ephemeral pool.
            let _ = sock.set_zero_linger();

            let mut buf = vec![0u8; msg.len()];
            let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();

            barrier.wait().await;
            let deadline = Instant::now() + duration;

            let mut count = 0u64;
            while Instant::now() < deadline {
                let t0 = if sample_latency {
                    Some(Instant::now())
                } else {
                    None
                };
                if sock.write_all(&msg).await.is_err() {
                    break;
                }
                if sock.read_exact(&mut buf).await.is_err() {
                    break;
                }
                if let Some(t0) = t0 {
                    let us = t0.elapsed().as_micros() as u64;
                    let _ = hist.record(us.max(1));
                }
                count += 1;
            }
            (count, hist)
        });
        handles.push(h);
    }

    // Release the barrier so all conns start in unison.
    barrier.wait().await;
    let start = Instant::now();

    let mut total = 0u64;
    let mut combined = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
    for h in handles {
        if let Ok((c, h)) = h.await {
            total += c;
            combined.add(h).ok();
        }
    }
    let elapsed = start.elapsed();
    let p50 = combined.value_at_quantile(0.50);
    let p99 = combined.value_at_quantile(0.99);
    WorkloadResult {
        ops: total,
        elapsed,
        p50_us: p50,
        p99_us: p99,
    }
}
