// HTTP/3 upload-isolated (server-RX) throughput workload.
//
// The send-side twin of `h3_echo`: each of `parallelism` worker tasks
// owns its own QUIC connection and, after the one-time handshake
// (skipped from the histogram), loops sending a POST to `/echo` with a
// `--body-bytes` request body — but the measured latency/RPS reflect
// *send completion* (request body fully written + FIN), NOT the echoed
// response. This isolates the QUIC RX direction on the server (decode +
// reassemble the uploaded STREAM frames) with minimal response handling.
//
// The h3 API requires the response stream be drained for the request to
// retire cleanly (and to surface server-side protocol errors), so after
// recording the send-completion latency we drain-and-discard the echoed
// body. Send-path errors and timeouts count as FAILED; a slow or
// errored *response drain* (post-measurement) does not move the latency
// numbers but is logged.
//
// Skip cert verification (the unikernel ships a self-signed dev cert;
// the workload measures throughput, not chain validation). The quinn /
// h3 / TLS setup is identical to `h3_health`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hdrhistogram::Histogram;
use http::Request;
use quinn::Endpoint;
use tokio::time::timeout;

use crate::WorkloadResult;
use crate::tls_util::{quic_client_config, resolve};

const PER_OP_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `f` only the first time the gate is `false`. Lets each
/// per-worker error path log once instead of once-per-iteration.
fn log_first<F: FnOnce(&mut bool)>(gate: &mut bool, f: F) {
    if !*gate {
        f(gate);
    }
}

// `NoCertVerify`, the QUIC client config, and `resolve` come from the
// shared `tls_util` module (see `crate::tls_util`).

pub async fn run(
    host: &str,
    port: u16,
    endpoint: &str,
    duration: Duration,
    warmup: Duration,
    parallelism: usize,
    body_bytes: usize,
) -> WorkloadResult {
    let server_addr = match resolve(host, port) {
        Some(a) => a,
        None => {
            eprintln!("h3_upload: failed to resolve {host}:{port}");
            return WorkloadResult {
                ops: 0,
                elapsed: duration,
                p50_us: 0,
                p99_us: 0,
            };
        }
    };

    let client_cfg = Arc::new(quic_client_config());
    let endpoint = Arc::new(endpoint.to_string());
    let host: Arc<str> = Arc::from(host.to_string().into_boxed_str());
    // Same `body_bytes` zeros every iteration; `Bytes` clone is a
    // refcount bump, not a copy.
    let body: Bytes = Bytes::from(vec![0u8; body_bytes]);

    let total_window = duration + warmup;
    let start = Instant::now();
    let measure_start = start + warmup;
    let deadline = start + total_window;

    let mut handles = Vec::with_capacity(parallelism);
    for worker_idx in 0..parallelism {
        let client_cfg = client_cfg.clone();
        let endpoint = endpoint.clone();
        let host = host.clone();
        let body = body.clone();
        let h = tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
            let mut count_post = 0u64;
            // Uploads that did NOT fully send (send/finish error or
            // timeout). The upload rate reflects send-completion, so a
            // failed send is the only failure mode that gates a count;
            // response-drain errors are logged but post-measurement.
            let mut failures_post = 0u64;
            // First-occurrence log gates: a single stuck connection
            // would otherwise spam stderr every few microseconds.
            let mut logged_send_err = false;
            let mut logged_send_timeout = false;
            let mut logged_data_err = false;
            let mut logged_finish_err = false;
            let mut logged_drain_err = false;

            // One QUIC endpoint (UDP socket) per worker so each worker
            // drives its own 4-tuple (the unikernel hashes datagrams to
            // per-core slot tables on the source-IP + source-port pair).
            let bind: std::net::SocketAddr = match server_addr {
                std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let mut quinn_ep = match Endpoint::client(bind) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("h3_upload[{worker_idx}]: bind failed: {e}");
                    return (count_post, failures_post, hist);
                }
            };
            quinn_ep.set_default_client_config((*client_cfg).clone());

            // Server name for SNI. NoCertVerify accepts anything, so
            // any string works.
            let conn = match timeout(
                PER_OP_TIMEOUT,
                quinn_ep.connect(server_addr, "waitless.local").unwrap(),
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    eprintln!("h3_upload[{worker_idx}]: connect failed: {e}");
                    return (count_post, failures_post, hist);
                }
                Err(_) => {
                    eprintln!("h3_upload[{worker_idx}]: connect timed out");
                    return (count_post, failures_post, hist);
                }
            };

            let h3_conn = h3_quinn::Connection::new(conn);
            let (mut driver, mut send_request) = match h3::client::new(h3_conn).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("h3_upload[{worker_idx}]: h3 init failed: {e}");
                    return (count_post, failures_post, hist);
                }
            };

            // Drive the H3 connection background task. It pumps QUIC
            // events into the h3 state machine; without this requests
            // stall after the first.
            let driver_task = tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });

            while Instant::now() < deadline {
                let t0 = Instant::now();
                let post_warmup = t0 >= measure_start;

                let req = Request::builder()
                    .method("POST")
                    .uri(format!("https://{}{}", host, endpoint))
                    .body(())
                    .unwrap();

                // Per-op error handling: log once per failure mode (not
                // once per iteration). The loadgen's stdout RPS / P50_US
                // / P99_US line is what the harness consumes; stderr is
                // for diagnostics only.
                let mut stream = match timeout(PER_OP_TIMEOUT, send_request.send_request(req)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        log_first(&mut logged_send_err, |once| {
                            eprintln!(
                                "h3_upload[{worker_idx}]: send_request err (logged once): {e}"
                            );
                            *once = true;
                        });
                        if post_warmup {
                            failures_post += 1;
                        }
                        continue;
                    }
                    Err(_) => {
                        log_first(&mut logged_send_timeout, |once| {
                            eprintln!(
                                "h3_upload[{worker_idx}]: send_request timed out (logged once)"
                            );
                            *once = true;
                        });
                        if post_warmup {
                            failures_post += 1;
                        }
                        continue;
                    }
                };

                // Send the request body, then FIN the send side. Upload
                // completion = body fully written + finish() returns.
                match timeout(PER_OP_TIMEOUT, stream.send_data(body.clone())).await {
                    Ok(Ok(())) => {}
                    _ => {
                        log_first(&mut logged_data_err, |once| {
                            eprintln!("h3_upload[{worker_idx}]: send_data failed (logged once)");
                            *once = true;
                        });
                        if post_warmup {
                            failures_post += 1;
                        }
                        continue;
                    }
                }
                match timeout(PER_OP_TIMEOUT, stream.finish()).await {
                    Ok(Ok(())) => {}
                    _ => {
                        log_first(&mut logged_finish_err, |once| {
                            eprintln!("h3_upload[{worker_idx}]: finish failed (logged once)");
                            *once = true;
                        });
                        if post_warmup {
                            failures_post += 1;
                        }
                        continue;
                    }
                }

                // The upload is complete at FIN — record the latency now,
                // BEFORE touching the response. This is the send/RX rate.
                if post_warmup {
                    let elapsed_us = t0.elapsed().as_micros() as u64;
                    let _ = hist.record(elapsed_us.max(1));
                    count_post += 1;
                }

                // Drain-and-discard the echoed response so the request
                // retires and the stream's resources are freed. This is
                // post-measurement: a drain error/timeout is logged but
                // does not move the upload latency/count (the upload
                // already completed). Errors here are protocol-level and
                // surface in the log only.
                let mut drained_ok = true;
                if timeout(PER_OP_TIMEOUT, stream.recv_response())
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
                {
                    loop {
                        match timeout(PER_OP_TIMEOUT, stream.recv_data()).await {
                            Ok(Ok(Some(_chunk))) => continue,
                            Ok(Ok(None)) => break, // full body drained
                            _ => {
                                drained_ok = false;
                                break;
                            }
                        }
                    }
                } else {
                    drained_ok = false;
                }
                if !drained_ok {
                    log_first(&mut logged_drain_err, |once| {
                        eprintln!(
                            "h3_upload[{worker_idx}]: response drain failed (post-measure, \
                             logged once)"
                        );
                        *once = true;
                    });
                }
            }

            // Tear down: dropping `send_request` lets the driver's
            // poll_close complete. Wait for the driver task so we don't
            // leak the endpoint's UDP socket beyond the worker's life.
            drop(send_request);
            let _ = driver_task.await;
            quinn_ep.close(0u32.into(), b"bye");
            quinn_ep.wait_idle().await;
            (count_post, failures_post, hist)
        });
        handles.push(h);
    }

    let mut total = 0u64;
    let mut total_failures = 0u64;
    let mut combined = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
    for h in handles {
        if let Ok((c, f, h)) = h.await {
            total += c;
            total_failures += f;
            combined.add(h).ok();
        }
    }
    // Surface uploads that never fully sent (FIN never landed) so a
    // stalled upload reads as a failure, not a phantom slow "success".
    // The harness parses only the RPS / P50_US / P99_US lines; this is
    // diagnostic.
    eprintln!("h3_upload: completed={total} failed={total_failures}");

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
