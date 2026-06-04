// Unified keep-alive HTTP throughput workload — HTTP/1.1, HTTP/2, and
// HTTP/3 in one subcommand (`loadgen http --proto h1|h2|h3`).
//
// This is the keep-alive GET hot path that `wrk` covered for HTTP/1.1
// only; here all three protocol versions share one client so an A/B
// across them is apples-to-apples (same runtime, same timing harness,
// same percentile sketch). It is the analogue of `h3_health` for h1/h2
// and subsumes it (`h3-health` stays for back-compat).
//
//   --connections  parallel transport connections (h2load `-c`)
//   --streams      concurrent in-flight requests *per connection*
//                  (h2load `-m`); forced to 1 for h1 (sequential
//                  keep-alive — HTTP/1.1 has no multiplexing).
//
// Every connection-task returns `(count_post_warmup, Histogram)`; the
// h2/h3 tasks fan out `streams` sub-tasks over the one multiplexed
// connection and merge their sub-histograms first. The top level then
// merges across connections.
//
// Cert verification is bypassed (the unikernel ships a self-signed dev
// cert; this measures throughput, not chain validation) — the
// `NoCertVerify` here mirrors the copies in `tls_handshake.rs` /
// `h3_health.rs`; they are deliberately kept per-file.

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::ValueEnum;
use hdrhistogram::Histogram;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::WorkloadResult;

const PER_OP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Proto {
    /// HTTP/1.1 over TLS (or plaintext with `--plaintext`).
    H1,
    /// HTTP/2 over TLS (ALPN "h2").
    H2,
    /// HTTP/3 over QUIC (ALPN "h3").
    H3,
}

// ── Cert verifier (accept anything — dev cert) ─────────────────────

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

/// TLS 1.3 client config for the TCP path (h1/h2), advertising the
/// given ALPN protocol(s). Resumption disabled so every connection's
/// first handshake is fresh (keep-alive amortises it anyway).
fn build_tcp_tls_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

fn build_quic_client_config() -> quinn::ClientConfig {
    let mut tls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg).expect("valid QUIC TLS config");
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(256u32.into())
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    cfg.transport_config(Arc::new(transport));
    cfg
}

fn resolve(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    let mut addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
    addrs.sort_by_key(|a| match a {
        std::net::SocketAddr::V4(_) => 0,
        std::net::SocketAddr::V6(_) => 1,
    });
    addrs.into_iter().next()
}

fn new_hist() -> Histogram<u64> {
    Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap()
}

// ── Entry point ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn run(
    proto: Proto,
    host: &str,
    port: u16,
    endpoint: &str,
    duration: Duration,
    warmup: Duration,
    connections: usize,
    streams: usize,
    plaintext: bool,
) -> WorkloadResult {
    let streams = streams.max(1);
    let connections = connections.max(1);
    if proto == Proto::H1 && streams > 1 {
        eprintln!("http: HTTP/1.1 has no multiplexing — ignoring --streams {streams} (using 1)");
    }
    if proto != Proto::H1 && plaintext {
        eprintln!("http: --plaintext ignored for {proto:?} (h2/h3 require TLS/QUIC)");
    }

    let start = Instant::now();
    let measure_start = start + warmup;
    let deadline = start + duration + warmup;

    let result = match proto {
        Proto::H1 => {
            run_h1(
                host,
                port,
                endpoint,
                connections,
                plaintext,
                measure_start,
                deadline,
            )
            .await
        }
        Proto::H2 => {
            run_h2(
                host,
                port,
                endpoint,
                connections,
                streams,
                measure_start,
                deadline,
            )
            .await
        }
        Proto::H3 => {
            run_h3(
                host,
                port,
                endpoint,
                connections,
                streams,
                measure_start,
                deadline,
            )
            .await
        }
    };

    let (total, combined) = result;
    WorkloadResult {
        ops: total,
        elapsed: duration,
        p50_us: combined.value_at_quantile(0.50),
        p99_us: combined.value_at_quantile(0.99),
    }
}

/// Join a set of `(count, Histogram)` connection-task handles into a
/// single aggregate.
async fn join_conns(
    handles: Vec<tokio::task::JoinHandle<(u64, Histogram<u64>)>>,
) -> (u64, Histogram<u64>) {
    let mut total = 0u64;
    let mut combined = new_hist();
    for h in handles {
        if let Ok((c, hist)) = h.await {
            total += c;
            combined.add(hist).ok();
        }
    }
    (total, combined)
}

// ── HTTP/1.1 keep-alive ────────────────────────────────────────────

async fn run_h1(
    host: &str,
    port: u16,
    endpoint: &str,
    connections: usize,
    plaintext: bool,
    measure_start: Instant,
    deadline: Instant,
) -> (u64, Histogram<u64>) {
    let request =
        format!("GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
    let request: Arc<[u8]> = Arc::from(request.into_bytes().into_boxed_slice());
    let host: Arc<str> = Arc::from(host.to_string().into_boxed_str());

    let connector = (!plaintext).then(|| {
        let cfg = build_tcp_tls_config(&[b"http/1.1"]);
        TlsConnector::from(cfg)
    });
    let server_name: ServerName<'static> = ServerName::try_from("localhost").unwrap();

    let mut handles = Vec::with_capacity(connections);
    for conn_idx in 0..connections {
        let request = Arc::clone(&request);
        let host = Arc::clone(&host);
        let connector = connector.clone();
        let server_name = server_name.clone();
        handles.push(tokio::spawn(async move {
            let mut hist = new_hist();
            let mut count = 0u64;
            let mut logged = false;

            let tcp = match timeout(PER_OP_TIMEOUT, TcpStream::connect((&*host, port))).await {
                Ok(Ok(s)) => s,
                _ => {
                    eprintln!("http[h1 c{conn_idx}]: connect failed");
                    return (count, hist);
                }
            };
            let _ = tcp.set_nodelay(true);

            if let Some(connector) = connector {
                match timeout(PER_OP_TIMEOUT, connector.connect(server_name, tcp)).await {
                    Ok(Ok(tls)) => {
                        h1_loop(
                            tls,
                            &request,
                            measure_start,
                            deadline,
                            &mut hist,
                            &mut count,
                            &mut logged,
                            conn_idx,
                        )
                        .await
                    }
                    _ => eprintln!("http[h1 c{conn_idx}]: TLS handshake failed"),
                }
            } else {
                h1_loop(
                    tcp,
                    &request,
                    measure_start,
                    deadline,
                    &mut hist,
                    &mut count,
                    &mut logged,
                    conn_idx,
                )
                .await
            }
            (count, hist)
        }));
    }
    join_conns(handles).await
}

/// Sequential keep-alive request loop over one already-established
/// (TLS or plain) stream.
#[allow(clippy::too_many_arguments)]
async fn h1_loop<S>(
    mut stream: S,
    request: &[u8],
    measure_start: Instant,
    deadline: Instant,
    hist: &mut Histogram<u64>,
    count: &mut u64,
    logged: &mut bool,
    conn_idx: usize,
) where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut leftover: Vec<u8> = Vec::new();
    let mut scratch = vec![0u8; 16 * 1024];
    while Instant::now() < deadline {
        let t0 = Instant::now();
        let post = t0 >= measure_start;
        if timeout(PER_OP_TIMEOUT, stream.write_all(request))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_none()
        {
            break;
        }
        match timeout(
            PER_OP_TIMEOUT,
            read_h1_response(&mut stream, &mut leftover, &mut scratch),
        )
        .await
        {
            Ok(true) => {}
            _ => {
                if !*logged {
                    eprintln!("http[h1 c{conn_idx}]: response read failed (logged once)");
                    *logged = true;
                }
                break;
            }
        }
        if post {
            let _ = hist.record((t0.elapsed().as_micros() as u64).max(1));
            *count += 1;
        }
    }
    let _ = stream.shutdown().await;
}

/// Read exactly one HTTP/1.1 response off `stream`, carrying any bytes
/// of the next response in `leftover`. Relies on `Content-Length`
/// (the bench endpoints always send it). Returns `false` on EOF/parse
/// failure before a full response.
async fn read_h1_response<S>(stream: &mut S, leftover: &mut Vec<u8>, scratch: &mut [u8]) -> bool
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = std::mem::take(leftover);
    loop {
        if let Some(hdr_end) = find_subsequence(&buf, b"\r\n\r\n") {
            let body_start = hdr_end + 4;
            let content_len = find_content_length(&buf[..hdr_end]).unwrap_or(0);
            let total = body_start + content_len;
            if buf.len() >= total {
                // Carry any bytes beyond this response forward.
                *leftover = buf.split_off(total);
                return true;
            }
        }
        match stream.read(scratch).await {
            Ok(0) => return false, // EOF before full response.
            Ok(n) => buf.extend_from_slice(&scratch[..n]),
            Err(_) => return false,
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Case-insensitive scan of the header block for `Content-Length`.
fn find_content_length(headers: &[u8]) -> Option<usize> {
    const KEY: &[u8] = b"content-length:";
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() < KEY.len() {
            continue;
        }
        if line[..KEY.len()].eq_ignore_ascii_case(KEY) {
            let val = &line[KEY.len()..];
            let s = std::str::from_utf8(val).ok()?.trim();
            return s.parse::<usize>().ok();
        }
    }
    None
}

// ── HTTP/2 (hyperium `h2`) keep-alive ──────────────────────────────

async fn run_h2(
    host: &str,
    port: u16,
    endpoint: &str,
    connections: usize,
    streams: usize,
    measure_start: Instant,
    deadline: Instant,
) -> (u64, Histogram<u64>) {
    let connector = TlsConnector::from(build_tcp_tls_config(&[b"h2"]));
    let server_name: ServerName<'static> = ServerName::try_from("localhost").unwrap();
    let uri: Arc<str> = Arc::from(format!("https://{host}{endpoint}").into_boxed_str());
    let host: Arc<str> = Arc::from(host.to_string().into_boxed_str());

    let mut handles = Vec::with_capacity(connections);
    for conn_idx in 0..connections {
        let connector = connector.clone();
        let server_name = server_name.clone();
        let uri = Arc::clone(&uri);
        let host = Arc::clone(&host);
        handles.push(tokio::spawn(async move {
            let tcp = match timeout(PER_OP_TIMEOUT, TcpStream::connect((&*host, port))).await {
                Ok(Ok(s)) => s,
                _ => {
                    eprintln!("http[h2 c{conn_idx}]: connect failed");
                    return (0u64, new_hist());
                }
            };
            let _ = tcp.set_nodelay(true);
            let tls = match timeout(PER_OP_TIMEOUT, connector.connect(server_name, tcp)).await {
                Ok(Ok(t)) => t,
                _ => {
                    eprintln!("http[h2 c{conn_idx}]: TLS handshake failed");
                    return (0u64, new_hist());
                }
            };

            let (send_request, connection) = match h2::client::handshake(tls).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("http[h2 c{conn_idx}]: h2 handshake failed: {e}");
                    return (0u64, new_hist());
                }
            };
            // Drive the connection: without polling it, no frames flow.
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });

            // Fan out `streams` concurrent request loops sharing the
            // one multiplexed connection. `SendRequest` is cheaply
            // cloneable; each clone gates on `ready()` (which respects
            // the peer's MAX_CONCURRENT_STREAMS).
            let mut subs = Vec::with_capacity(streams);
            for _ in 0..streams {
                let mut send = send_request.clone();
                let uri = Arc::clone(&uri);
                subs.push(tokio::spawn(async move {
                    let mut hist = new_hist();
                    let mut count = 0u64;
                    let mut logged = false;
                    while Instant::now() < deadline {
                        let t0 = Instant::now();
                        let post = t0 >= measure_start;
                        send = match send.ready().await {
                            Ok(s) => s,
                            Err(_) => break,
                        };
                        let req = match http::Request::builder()
                            .method(http::Method::GET)
                            .uri(&*uri)
                            .body(())
                        {
                            Ok(r) => r,
                            Err(_) => break,
                        };
                        let (resp_fut, _body) = match send.send_request(req, true) {
                            Ok(x) => x,
                            Err(e) => {
                                if !logged {
                                    eprintln!("http[h2]: send_request err (once): {e}");
                                    logged = true;
                                }
                                continue;
                            }
                        };
                        let resp = match resp_fut.await {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                        let mut body = resp.into_body();
                        let mut ok = true;
                        while let Some(chunk) = body.data().await {
                            match chunk {
                                Ok(c) => {
                                    let _ = body.flow_control().release_capacity(c.len());
                                }
                                Err(_) => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok && post {
                            let _ = hist.record((t0.elapsed().as_micros() as u64).max(1));
                            count += 1;
                        }
                    }
                    (count, hist)
                }));
            }
            // Drop our extra handle so the connection can close once
            // every sub-task's clone is gone.
            drop(send_request);

            let mut total = 0u64;
            let mut combined = new_hist();
            for s in subs {
                if let Ok((c, h)) = s.await {
                    total += c;
                    combined.add(h).ok();
                }
            }
            driver.abort();
            (total, combined)
        }));
    }
    join_conns(handles).await
}

// ── HTTP/3 (quinn + h3) keep-alive ─────────────────────────────────

async fn run_h3(
    host: &str,
    port: u16,
    endpoint: &str,
    connections: usize,
    streams: usize,
    measure_start: Instant,
    deadline: Instant,
) -> (u64, Histogram<u64>) {
    let server_addr = match resolve(host, port) {
        Some(a) => a,
        None => {
            eprintln!("http[h3]: failed to resolve {host}:{port}");
            return (0, new_hist());
        }
    };
    let client_cfg = Arc::new(build_quic_client_config());
    let uri: Arc<str> = Arc::from(format!("https://{host}{endpoint}").into_boxed_str());

    let mut handles = Vec::with_capacity(connections);
    for conn_idx in 0..connections {
        let client_cfg = Arc::clone(&client_cfg);
        let uri = Arc::clone(&uri);
        handles.push(tokio::spawn(async move {
            let bind: std::net::SocketAddr = match server_addr {
                std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let mut quinn_ep = match quinn::Endpoint::client(bind) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("http[h3 c{conn_idx}]: bind failed: {e}");
                    return (0u64, new_hist());
                }
            };
            quinn_ep.set_default_client_config((*client_cfg).clone());

            let conn = match timeout(
                PER_OP_TIMEOUT,
                quinn_ep.connect(server_addr, "waitless.local").unwrap(),
            )
            .await
            {
                Ok(Ok(c)) => c,
                _ => {
                    eprintln!("http[h3 c{conn_idx}]: connect failed");
                    return (0u64, new_hist());
                }
            };

            let h3_conn = h3_quinn::Connection::new(conn);
            let (mut driver, send_request) = match h3::client::new(h3_conn).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("http[h3 c{conn_idx}]: h3 init failed: {e}");
                    return (0u64, new_hist());
                }
            };
            let driver_task = tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });

            let mut subs = Vec::with_capacity(streams);
            for _ in 0..streams {
                let mut send = send_request.clone();
                let uri = Arc::clone(&uri);
                subs.push(tokio::spawn(async move {
                    let mut hist = new_hist();
                    let mut count = 0u64;
                    let mut logged = false;
                    while Instant::now() < deadline {
                        let t0 = Instant::now();
                        let post = t0 >= measure_start;
                        let req = match http::Request::builder()
                            .method(http::Method::GET)
                            .uri(&*uri)
                            .body(())
                        {
                            Ok(r) => r,
                            Err(_) => break,
                        };
                        let mut stream = match timeout(PER_OP_TIMEOUT, send.send_request(req)).await
                        {
                            Ok(Ok(s)) => s,
                            _ => {
                                if !logged {
                                    eprintln!("http[h3]: send_request failed (once)");
                                    logged = true;
                                }
                                continue;
                            }
                        };
                        if timeout(PER_OP_TIMEOUT, stream.finish()).await.is_err() {
                            continue;
                        }
                        if timeout(PER_OP_TIMEOUT, stream.recv_response())
                            .await
                            .is_err()
                        {
                            continue;
                        }
                        let mut ok = true;
                        loop {
                            match timeout(PER_OP_TIMEOUT, stream.recv_data()).await {
                                Ok(Ok(Some(_))) => continue,
                                Ok(Ok(None)) => break,
                                _ => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok && post {
                            let _ = hist.record((t0.elapsed().as_micros() as u64).max(1));
                            count += 1;
                        }
                    }
                    (count, hist)
                }));
            }
            drop(send_request);

            let mut total = 0u64;
            let mut combined = new_hist();
            for s in subs {
                if let Ok((c, h)) = s.await {
                    total += c;
                    combined.add(h).ok();
                }
            }
            let _ = driver_task.await;
            quinn_ep.close(0u32.into(), b"bye");
            quinn_ep.wait_idle().await;
            (total, combined)
        }));
    }
    join_conns(handles).await
}
