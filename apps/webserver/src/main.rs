// UniKernel Example: HTTP Web Server
//
// `#[uni::boot]` marks the entry point; the `WebServerApp` type
// holds long-lived state (the HTTP server) and gets handed to the
// runtime via `uni::run`. Request handlers and diagnostic endpoints
// are defined further down.

#![no_std]

extern crate alloc;
extern crate uni;
extern crate uni_http;
extern crate uni_tls;

use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;

use uni::net::{Net, NetBringUp};
use uni_http::{Request, Response};

// ---- Application ------------------------------------------------------------

/// Plain HTTP listener port. `uni::config_port` lets the runner
/// override this via env var; the argument is the default.
const HTTP_PORT: u16 = 80;

/// HTTPS listener port. Runs alongside HTTP so apps can be reached
/// over both protocols with the same routes. The HVF runner / QEMU
/// user-mode networking forward host ports to these (conventionally
/// 8080 → :80 and 8443 → :443).
const HTTPS_PORT: u16 = 443;

/// "Gateway" / sidecar pattern listener: accept TCP, on each request
/// fan out to a UDP backend, await the reply, return it. Demonstrates
/// the async-runtime + datapath win on the request shape that
/// dominates real microservice deployments (BFFs, API gateways).
/// `gateway_max` in the bench harness drives this.
const GATEWAY_PORT: u16 = 9000;

/// Where the gateway forwards UDP datagrams. Loadgen runs an echo
/// server on this port on the same host the unikernel virtualises
/// under (or `127.0.0.1` for native). The address is resolved at
/// boot from `Net::gateway()` (DHCP-discovered host IP under HVF /
/// QEMU NAT) and combined with this fixed port.
const GATEWAY_BACKEND_PORT: u16 = 7777;

/// Wire payload size. Loadgen sends and receives this many bytes per
/// request; the unikernel forwards the same byte-for-byte. Sized to
/// match an L1-fitting cache line round-trip while still triggering
/// real packet send/recv cycles.
const GATEWAY_MSG_SIZE: usize = 32;

/// Holds the long-lived state of the webserver program.
///
/// Dropping `WebServerApp` drops every listener handle (each
/// aborts its per-worker accept task and releases its port) and
/// the `Net` handle (which marks the stack disabled). In-flight
/// connections drain naturally at their idle timeout.
struct WebServerApp {
    _http: Option<uni::runtime::TcpHandle>,
    _https: Option<uni::runtime::TcpHandle>,
    _udp_echo: Option<uni::runtime::UdpHandle>,
    _tcp_echo: Option<uni::runtime::TcpHandle>,
    _gateway: Option<uni::runtime::TcpHandle>,
    _net: Net,
}

impl uni::App for WebServerApp {}

impl WebServerApp {
    fn new(net: Net) -> Self {
        uni::log(b"Starting HTTP server...\n");
        let http_port = uni::config_port(HTTP_PORT);
        let https_port = uni::config_tls_port(HTTPS_PORT);

        let udp_echo = match uni::runtime::UdpSocket::bind(7) {
            Ok(sock) => {
                let h = sock.run(|sock| async move {
                    let mut buf = [0u8; 1500];
                    loop {
                        let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
                        let _ = sock.send_to(src_ip, src_port, &buf[..n]);
                    }
                });
                uni::log(b"UDP echo server on port 7 (async, per-worker)\n");
                Some(h)
            }
            Err(_) => {
                uni::log(b"UDP echo: bind FAILED\n");
                None
            }
        };

        let tcp_echo = match uni::runtime::TcpListener::bind(9) {
            Ok(listener) => {
                let h = listener.run(|stream| async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        // 30s idle timeout via `timeout_us` — exercises
                        // the `select` combinator end-to-end. In a
                        // steady echo flow the recv wins every time;
                        // on an abandoned connection the timer fires
                        // and we tear down rather than leak the slot.
                        let got = uni::runtime::timeout_us(
                            30_000_000,
                            stream.recv(&mut buf),
                        )
                        .await;
                        let Some(n) = got else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        if stream.send(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
                uni::log(b"TCP echo server on port 9 (async, per-worker)\n");
                Some(h)
            }
            Err(_) => {
                uni::log(b"TCP echo: bind FAILED\n");
                None
            }
        };

        // Gateway listener — the `gateway_max` workload's server
        // side. Each accepted TCP conn binds its own ephemeral
        // UDP socket once (reused across every request on the
        // conn) and loops:
        //   tcp_recv → udp_send_to(backend) → udp_recv → tcp_send.
        //
        // Both `udp_recv` and `tcp_recv` park the conn's task on
        // the runtime's per-worker reactor — under high concurrency
        // (~64 conns / core) the worker juggles dozens of in-flight
        // forwards instead of stalling on each. That fan-out is the
        // exact pattern API gateways / sidecars run in production,
        // and it's the workload where async + a syscall-free
        // datapath compound: every Linux equivalent pays >5 syscalls
        // per request just to get bytes through the kernel TCP +
        // UDP stacks.
        let backend_ip = net.gateway().0;
        let gateway = match uni::runtime::TcpListener::bind(GATEWAY_PORT) {
            Ok(listener) => {
                let h = listener.run(move |stream| async move {
                    let udp = match uni::runtime::UdpSocket::open_ephemeral() {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let mut buf = [0u8; GATEWAY_MSG_SIZE];
                    loop {
                        // Drain exactly one full request from the
                        // peer. Loadgen sends fixed-size pings, so
                        // a partial recv only happens at conn close.
                        let mut got = 0;
                        while got < GATEWAY_MSG_SIZE {
                            let n = stream.recv(&mut buf[got..]).await;
                            if n == 0 {
                                return;
                            }
                            got += n;
                        }
                        if udp
                            .send_to(backend_ip, GATEWAY_BACKEND_PORT, &buf)
                            .is_err()
                        {
                            return;
                        }
                        let (_, _, n) = udp.recv_from(&mut buf).await;
                        if n != GATEWAY_MSG_SIZE {
                            return;
                        }
                        if stream.send(&buf).await.is_err() {
                            return;
                        }
                    }
                });
                uni::log(b"Gateway listener on port 9000 (async fan-out to UDP backend)\n");
                Some(h)
            }
            Err(_) => {
                uni::log(b"Gateway: bind FAILED\n");
                None
            }
        };

        let http = match uni_http::listen(http_port, handle_request) {
            Ok(h) => Some(h),
            Err(_) => {
                uni::log(b"http: bind FAILED\n");
                None
            }
        };

        // HTTPS is opt-in: if the bundled dev cert/key parse,
        // bind the HTTPS port; otherwise log + skip.
        let https = match uni_tls::acceptor(DEV_CERT_DER, DEV_KEY_PKCS8_DER) {
            Ok(tls) => {
                uni::log(b"TLS: dev cert loaded. Serving HTTPS.\n");
                match uni_http::listen_https(https_port, handle_request, tls) {
                    Ok(h) => Some(h),
                    Err(_) => {
                        uni::log(b"https: bind FAILED\n");
                        None
                    }
                }
            }
            Err(_) => {
                uni::log(b"TLS: failed to parse dev cert/key; HTTPS disabled.\n");
                None
            }
        };

        uni::log(b"Entering event loop.\n");
        WebServerApp {
            _http: http,
            _https: https,
            _udp_echo: udp_echo,
            _tcp_echo: tcp_echo,
            _gateway: gateway,
            _net: net,
        }
    }
}

impl Drop for WebServerApp {
    fn drop(&mut self) {
        uni::log(b"[app] shutting down\n");
    }
}

#[uni::boot]
async fn boot() {
    log_boot_info();

    // Try DHCP first; on timeout (typical under minimal tap
    // networks) fall back to a static 10.0.2.15/24 config so the
    // app still boots. `Net::enable` leaves the ENABLED flag clear
    // when bring-up fails, which is what makes the fallback valid.
    let net = match Net::enable(NetBringUp::Dhcp).await {
        Ok(n) => n,
        Err(_) => {
            uni::log(b"Net::enable: DHCP failed, using 10.0.2.15/24 static fallback\n");
            Net::enable(NetBringUp::Static {
                ip: uni::net::Ipv4Addr::new(10, 0, 2, 15),
                gateway: uni::net::Ipv4Addr::new(10, 0, 2, 2),
                netmask: uni::net::Ipv4Addr::new(255, 255, 255, 0),
            })
            .await
            .expect("Net::enable: both DHCP and static fallback failed")
        }
    };
    uni::run(WebServerApp::new(net));
}

// ---- Request dispatch + route handlers --------------------------------------

fn handle_request(req: &Request) -> Response {
    match req.path() {
        b"/" => Response::ok(b"text/html", INDEX_HTML),
        b"/health" => Response::ok(b"application/json", HEALTH_JSON),
        b"/stats" => stats_response(),
        b"/heap" => heap_response(),
        b"/compute" => {
            // black_box prevents the compiler from eliminating compute_work()
            // as dead code (the return value would otherwise be unused).
            core::hint::black_box(compute_work());
            Response::ok(b"application/json", b"{\"status\":\"computed\"}")
        }
        b"/tls_profile" => tls_profile_response(),
        b"/tls_profile_reset" => {
            uni_tls::tls_profile_reset();
            Response::ok(b"text/plain", b"tls profile reset\n")
        }
        _ => Response::not_found(),
    }
}

/// Emit the contents of `uni::boot_info()` at startup. The line tags
/// (`BOOT_INFO ram=...`) are stable so the webserver integration test
/// can grep them out of the serial log.
fn log_boot_info() {
    let bi = uni::boot_info();
    let mut line: String = String::new();
    let _ = write!(
        line,
        "BOOT_INFO ram={} cpus={} nics={} boot_args=\"{}\"\n",
        bi.ram_bytes,
        bi.num_cpus,
        bi.nics.len(),
        bi.boot_args,
    );
    uni::log(line.as_bytes());
    for (i, nic) in bi.nics.iter().enumerate() {
        let mut l: String = String::new();
        let _ = write!(
            l,
            "BOOT_INFO nic[{}] name={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} qps={}\n",
            i,
            nic.name,
            nic.mac[0], nic.mac[1], nic.mac[2], nic.mac[3], nic.mac[4], nic.mac[5],
            nic.num_queue_pairs,
        );
        uni::log(l.as_bytes());
    }
}

/// CPU-intensive work: iterative FNV-1a over 100K inputs. Dominates
/// per-request cost, making multi-core distribution visible under
/// `/compute` benchmarks.
fn compute_work() -> u32 {
    let mut h: u32 = 2166136261;
    for i in 0..100_000u32 {
        h ^= i;
        h = h.wrapping_mul(16777619);
    }
    h
}

// ---- Static resources -------------------------------------------------------

const HEALTH_JSON: &[u8] =
    b"{\"status\":\"ok\",\"runtime\":\"unikernel\",\"version\":\"0.1.0\"}";

const INDEX_HTML: &[u8] = b"<!DOCTYPE html>\
<html><head><title>UniKernel</title>\
<style>\
body { font-family: system-ui, sans-serif; max-width: 800px; \
margin: 40px auto; padding: 0 20px; background: #0a0a0a; color: #e0e0e0; }\
h1 { color: #4fc3f7; } pre { background: #1a1a2e; padding: 16px; \
border-radius: 8px; overflow-x: auto; } a { color: #4fc3f7; }\
.stat { display: inline-block; margin: 8px 16px 8px 0; padding: 8px 16px; \
background: #1a1a2e; border-radius: 4px; }\
</style></head><body>\
<h1>UniKernel Web Server</h1>\
<p>Running directly on bare metal \xe2\x80\x94 no OS kernel, no syscalls.</p>\
<div>\
<span class='stat'>Ring 0 execution</span>\
<span class='stat'>Single address space</span>\
<span class='stat'>In-process I/O</span>\
<span class='stat'>Virtio-net driver</span>\
</div>\
<h2>Architecture</h2>\
<pre>\
Application (this server)\n\
    |  direct function call\n\
    v\n\
HTTP parser\n\
    |  uni:: interface\n\
    v\n\
TCP stack (uni::tcp)\n\
    |  unikernel: net::tcp + virtio-net\n\
    |  native:    POSIX sockets\n\
    v\n\
Network backend\n\
</pre>\
<h2>Endpoints</h2>\
<ul>\
<li><a href='/'>/ </a> \xe2\x80\x94 this page</li>\
<li><a href='/health'>/health</a> \xe2\x80\x94 health check (JSON)</li>\
<li><a href='/stats'>/stats</a> \xe2\x80\x94 runtime statistics</li>\
</ul>\
<p><small>UniKernel v0.1.0</small></p>\
</body></html>";

// Checked-in self-signed ECDSA P-256 dev cert + private key, baked
// into the binary via include_bytes!. See apps/webserver/dev_certs/
// README.md for details and the regen.sh script. DO NOT USE IN
// PRODUCTION.
const DEV_CERT_DER: &[u8] = include_bytes!("../dev_certs/dev_cert.der");
const DEV_KEY_PKCS8_DER: &[u8] = include_bytes!("../dev_certs/dev_key.der");

// ---- Diagnostic endpoints ---------------------------------------------------

/// Per-queue RX frame counts + used-ring cursors, so we can see how
/// the NIC is distributing flows under Tier 1 multi-queue. A
/// diagnostic, not a production dashboard. If `device_idx` moves
/// but `counts` stays 0, there's a polling bug; if neither moves,
/// the host side isn't delivering to that queue.
fn stats_response() -> Response {
    let counts = uni::net_rx_counts();
    let cursors = uni::net_rx_used_cursors();
    let nqp = uni::net_num_queue_pairs() as usize;

    let mut body = String::from("{\"rx_frames\":[");
    for i in 0..nqp.min(counts.len()) {
        if i > 0 { body.push(','); }
        let _ = write!(body, "{}", counts[i]);
    }
    body.push_str("],\"rx_used_dev\":[");
    for i in 0..nqp.min(cursors.len()) {
        if i > 0 { body.push(','); }
        let _ = write!(body, "{}", cursors[i].0);
    }
    body.push_str("],\"rx_used_drv\":[");
    for i in 0..nqp.min(cursors.len()) {
        if i > 0 { body.push(','); }
        let _ = write!(body, "{}", cursors[i].1);
    }
    let _ = write!(body, "],\"num_queue_pairs\":{}}}", nqp);

    Response::ok_owned(b"application/json", body.into_bytes().into_boxed_slice())
}

/// Snapshot of kernel heap utilisation (allocated / available /
/// claimed / fragmentation).
fn heap_response() -> Response {
    let s = uni::heap_stats();
    let body = format!(
        "{{\"allocated_bytes\":{},\"available_bytes\":{},\"claimed_bytes\":{},\
         \"allocation_count\":{},\"fragment_count\":{},\"total_allocation_count\":{}}}",
        s.allocated_bytes,
        s.available_bytes,
        s.claimed_bytes,
        s.allocation_count,
        s.fragment_count,
        s.total_allocation_count,
    );
    Response::ok_owned(b"application/json", body.into_bytes().into_boxed_slice())
}

/// TLS handshake profiler output as plain text. The profiler fills
/// a caller-provided byte slice (see `net::tls_server::profile`),
/// so this path stays on the `Vec<u8>` API rather than `format!`.
const PROFILE_BUF_LEN: usize = 4096;

fn tls_profile_response() -> Response {
    let mut buf = alloc::vec![0u8; PROFILE_BUF_LEN];
    let n = uni_tls::tls_profile_report(buf.as_mut_slice());
    buf.truncate(n);
    Response::ok_owned(b"text/plain", buf.into_boxed_slice())
}
