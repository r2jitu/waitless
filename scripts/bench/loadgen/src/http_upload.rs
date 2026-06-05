// Bulk-RX upload workload: keep-alive HTTP/1.1 POST with sized
// body, tiny response. Plain TCP or TLS depending on `--tls`.
//
// Per iteration on each connection: write `Content-Length:
// msg_size` request + body, read 200 OK response, repeat. The
// server's RX path sees ~msg_size/MSS segments per request — the
// shape RSC / HW-GRO wants to coalesce on the gVNIC driver.
//
// Latency samples from connection 0 only (cheap, representative).
// Connections share a barrier so per-conn ramp doesn't skew
// aggregate throughput.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use tokio_rustls::TlsConnector;

use crate::WorkloadResult;
use crate::tls_util::tcp_tls_config;

pub async fn run(
    host: &str,
    port: u16,
    endpoint: &str,
    duration: Duration,
    connections: usize,
    msg_size: usize,
    tls: bool,
) -> WorkloadResult {
    let host_arc: Arc<str> = Arc::from(host.to_string().into_boxed_str());

    // Build the POST request once: headers (with Content-Length set
    // to msg_size) followed by `msg_size` bytes of 'p'. Send the same
    // bytes every iteration — the server discards them.
    let header = format!(
        "POST {endpoint} HTTP/1.1\r\nHost: {host}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {msg_size}\r\n\r\n",
    );
    let mut req_bytes = Vec::with_capacity(header.len() + msg_size);
    req_bytes.extend_from_slice(header.as_bytes());
    req_bytes.resize(req_bytes.len() + msg_size, b'p');
    let request: Arc<[u8]> = Arc::from(req_bytes.into_boxed_slice());

    let tls_setup: Option<(TlsConnector, ServerName<'static>)> = if tls {
        let cfg = tcp_tls_config(&[], Resumption::disabled());
        let connector = TlsConnector::from(cfg);
        let server_name: ServerName<'static> = ServerName::try_from("localhost").unwrap();
        Some((connector, server_name))
    } else {
        None
    };

    let barrier = Arc::new(Barrier::new(connections + 1));
    let mut handles = Vec::with_capacity(connections);
    for i in 0..connections {
        let host = Arc::clone(&host_arc);
        let request = Arc::clone(&request);
        let barrier = Arc::clone(&barrier);
        let tls_setup = tls_setup.clone();
        let sample_latency = i == 0;
        let h = tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
            let mut count = 0u64;

            // Open the conn (TLS or plain) once and keep it for the
            // whole run. Bail out (count=0) on any setup failure.
            let result = if let Some((connector, server_name)) = tls_setup {
                let tcp = match TcpStream::connect((&*host, port)).await {
                    Ok(s) => s,
                    Err(_) => {
                        barrier.wait().await;
                        return (0u64, hist);
                    }
                };
                let _ = tcp.set_nodelay(true);
                let stream = match connector.connect(server_name.clone(), tcp).await {
                    Ok(s) => s,
                    Err(_) => {
                        barrier.wait().await;
                        return (0u64, hist);
                    }
                };
                barrier.wait().await;
                let deadline = Instant::now() + duration;
                run_loop(
                    stream,
                    &request,
                    deadline,
                    sample_latency,
                    &mut hist,
                    &mut count,
                )
                .await
            } else {
                let tcp = match TcpStream::connect((&*host, port)).await {
                    Ok(s) => s,
                    Err(_) => {
                        barrier.wait().await;
                        return (0u64, hist);
                    }
                };
                let _ = tcp.set_nodelay(true);
                barrier.wait().await;
                let deadline = Instant::now() + duration;
                run_loop(
                    tcp,
                    &request,
                    deadline,
                    sample_latency,
                    &mut hist,
                    &mut count,
                )
                .await
            };
            let _ = result;
            (count, hist)
        });
        handles.push(h);
    }

    barrier.wait().await;
    let start = Instant::now();

    let mut total = 0u64;
    let mut combined = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
    for h in handles {
        if let Ok((c, hist)) = h.await {
            total += c;
            combined.add(hist).ok();
        }
    }

    WorkloadResult {
        ops: total,
        elapsed: start.elapsed(),
        p50_us: combined.value_at_quantile(0.50),
        p99_us: combined.value_at_quantile(0.99),
    }
}

async fn run_loop<S>(
    mut stream: S,
    request: &[u8],
    deadline: Instant,
    sample_latency: bool,
    hist: &mut Histogram<u64>,
    count: &mut u64,
) -> bool
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; 1024];
    while Instant::now() < deadline {
        let t0 = if sample_latency {
            Some(Instant::now())
        } else {
            None
        };
        if stream.write_all(request).await.is_err() {
            return false;
        }
        // Drain one response. The server's reply is small JSON;
        // read a fixed window and look for the end-of-headers
        // marker. A successful 200 OK has Content-Length set, so
        // a single read typically returns headers + body together.
        if !read_one_response(&mut stream, &mut buf).await {
            return false;
        }
        if let Some(t0) = t0 {
            let _ = hist.record((t0.elapsed().as_micros() as u64).max(1));
        }
        *count += 1;
    }
    true
}

/// Read until we see end-of-headers (`\r\n\r\n`) plus
/// Content-Length-many body bytes. The /discard response is
/// `{"status":"discarded"}` (22 bytes) — Content-Length: 22.
/// Total response is well under 1 KiB; one or two `read`s suffice.
async fn read_one_response<S>(stream: &mut S, buf: &mut [u8]) -> bool
where
    S: AsyncReadExt + Unpin,
{
    let mut filled = 0usize;
    let mut headers_end: Option<usize> = None;
    let mut content_length: Option<usize> = None;

    loop {
        let n = match stream.read(&mut buf[filled..]).await {
            Ok(0) => return false,
            Ok(n) => n,
            Err(_) => return false,
        };
        filled += n;

        if headers_end.is_none() {
            if let Some(idx) = find_subslice(&buf[..filled], b"\r\n\r\n") {
                headers_end = Some(idx + 4);
                content_length = parse_content_length(&buf[..idx]);
            }
        }
        if let (Some(end), Some(cl)) = (headers_end, content_length) {
            if filled >= end + cl {
                return true;
            }
        }
        if filled == buf.len() {
            // Response larger than our buffer — bench is broken;
            // bail.
            return false;
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let needle = b"content-length:";
    let n = headers.len();
    let nl = needle.len();
    let mut i = 0;
    while i + nl <= n {
        let matches = headers[i..i + nl]
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b));
        if matches {
            let rest = &headers[i + nl..];
            let line_end = rest.iter().position(|&b| b == b'\r').unwrap_or(rest.len());
            let value = core::str::from_utf8(&rest[..line_end]).ok()?.trim();
            return value.parse::<usize>().ok();
        }
        i += 1;
    }
    None
}
