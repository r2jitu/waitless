// Open-loop fixed-rate HTTP/1.1 workload — the latency-under-load
// harness (`loadgen http-rate --rate N`).
//
// The closed-loop workloads (`http`, wrk) measure latency at
// *whatever rate the server gives back*: a slow response slows the
// next request down, so the measured distribution self-throttles and
// hides queueing (coordinated omission). This workload is the wrk2
// shape instead: requests fire on a fixed global schedule
// (`rate` req/s spread evenly over `connections` keep-alive conns,
// per-conn start offsets staggered), and every latency sample is
// measured **from the request's scheduled time**, not its actual
// send time. A server that falls behind sees the backlog charged to
// its tail percentiles — exactly what an arriving open-world user
// would experience.
//
// HTTP/1.1 has no multiplexing, so one in-flight request per conn:
// when a response arrives after the conn's next scheduled slot, the
// following request goes out immediately (no sleep) and its latency
// still counts from its schedule. Size `connections` so the per-conn
// rate stays comfortably below 1/latency, or the conn itself becomes
// the bottleneck (the tool reports achieved vs target rate so this
// is visible).

use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{sleep_until, timeout};
use tokio_rustls::TlsConnector;

use crate::WorkloadResult;
use crate::http_load::read_h1_response;
use crate::tls_util::tcp_tls_config;

const PER_OP_TIMEOUT: Duration = Duration::from_secs(10);

fn new_hist() -> Histogram<u64> {
    // 1 µs .. 60 s, 3 significant digits.
    Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap()
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    host: &str,
    port: u16,
    endpoint: &str,
    rate: u64,
    connections: usize,
    duration: Duration,
    warmup: Duration,
    plaintext: bool,
) -> WorkloadResult {
    let connections = connections.max(1);
    let interval = Duration::from_secs_f64(connections as f64 / rate as f64);

    let request =
        format!("GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
    let request: Arc<[u8]> = Arc::from(request.into_bytes().into_boxed_slice());
    let host_arc: Arc<str> = Arc::from(host.to_string().into_boxed_str());

    let connector = (!plaintext).then(|| {
        let cfg = tcp_tls_config(&[b"http/1.1"], Resumption::disabled());
        TlsConnector::from(cfg)
    });
    let server_name: ServerName<'static> = ServerName::try_from("localhost").unwrap();

    let start = Instant::now();
    let measure_start = start + warmup;
    let deadline = start + warmup + duration;

    let mut handles = Vec::with_capacity(connections);
    for conn_idx in 0..connections {
        let request = Arc::clone(&request);
        let host = Arc::clone(&host_arc);
        let connector = connector.clone();
        let server_name = server_name.clone();
        // Stagger conn start offsets across one interval so the
        // aggregate schedule is a smooth `rate` req/s, not
        // `connections`-sized bursts every interval.
        let first_at = start + interval.mul_f64(conn_idx as f64 / connections as f64);
        handles.push(tokio::spawn(async move {
            let mut hist = new_hist();
            let mut sent = 0u64;
            let mut errors = 0u64;

            let tcp = match timeout(PER_OP_TIMEOUT, TcpStream::connect((&*host, port))).await {
                Ok(Ok(s)) => s,
                _ => return (0, 1, hist),
            };
            let _ = tcp.set_nodelay(true);

            macro_rules! drive {
                ($stream:expr) => {{
                    let mut stream = $stream;
                    let mut leftover: Vec<u8> = Vec::new();
                    let mut scratch = vec![0u8; 16 * 1024];
                    let mut scheduled = first_at;
                    loop {
                        if scheduled < Instant::now() - Duration::from_secs(30) {
                            // Hopelessly behind (>30 s of backlog on this
                            // conn): the per-conn rate exceeds 1/latency.
                            // Stop rather than report meaningless hours.
                            errors += 1;
                            break;
                        }
                        sleep_until(scheduled.into()).await;
                        if Instant::now() >= deadline {
                            break;
                        }
                        use tokio::io::AsyncWriteExt;
                        let ok = timeout(PER_OP_TIMEOUT, stream.write_all(&request))
                            .await
                            .ok()
                            .and_then(|r| r.ok())
                            .is_some()
                            && matches!(
                                timeout(
                                    PER_OP_TIMEOUT,
                                    read_h1_response(&mut stream, &mut leftover, &mut scratch),
                                )
                                .await,
                                Ok(true)
                            );
                        let done = Instant::now();
                        if !ok {
                            errors += 1;
                            break;
                        }
                        if done >= measure_start && scheduled >= measure_start {
                            // Latency from the SCHEDULE, not the send —
                            // the coordinated-omission correction.
                            let us = done.duration_since(scheduled).as_micros() as u64;
                            hist.record(us.max(1)).ok();
                            sent += 1;
                        }
                        scheduled += interval;
                    }
                }};
            }

            if let Some(connector) = connector {
                match timeout(PER_OP_TIMEOUT, connector.connect(server_name, tcp)).await {
                    Ok(Ok(tls)) => drive!(tls),
                    _ => return (0, 1, hist),
                }
            } else {
                drive!(tcp)
            }
            let _ = conn_idx;
            (sent, errors, hist)
        }));
    }

    let mut total = 0u64;
    let mut errors = 0u64;
    let mut combined = new_hist();
    for h in handles {
        if let Ok((c, e, hist)) = h.await {
            total += c;
            errors += e;
            combined.add(hist).ok();
        }
    }

    // Extended, machine-parseable lines beyond the common
    // RPS/P50/P99 trio that `print_result` emits.
    println!("TARGET_RPS {rate}");
    println!(
        "ACHIEVED_RPS {:.0}",
        total as f64 / duration.as_secs_f64().max(1e-6)
    );
    println!("ERRORS {errors}");
    println!("P90_US {}", combined.value_at_quantile(0.90));
    println!("P999_US {}", combined.value_at_quantile(0.999));
    println!("MAX_US {}", combined.max());

    WorkloadResult {
        ops: total,
        elapsed: duration,
        p50_us: combined.value_at_quantile(0.50),
        p99_us: combined.value_at_quantile(0.99),
    }
}
