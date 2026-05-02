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

use uni::net::Net;
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
/// request; the unikernel forwards the same byte-for-byte.
const GATEWAY_MSG_SIZE: usize = 32;

/// Long-lived program state.
///
/// `handles` carries every value whose `Drop` runs the listener /
/// network teardown — TCP / UDP listener handles plus the `Net`
/// guard. Storing them via `uni::Handles` instead of named
/// `_field: Option<Handle>` slots keeps the "this exists for its
/// drop side effect" intent explicit.
struct WebServerApp {
    // load-bearing: every entry's `Drop` aborts a listener task
    // or tears down the network stack at shutdown.
    #[allow(dead_code)]
    handles: uni::Handles,
}

impl Drop for WebServerApp {
    fn drop(&mut self) {
        uni::println!("[app] shutting down");
    }
}

#[uni::boot]
async fn boot() {
    log_boot_info();

    // One-line DHCP-with-static-fallback. The runtime tries DHCP
    // first; on bring-up failure (typical under minimal tap
    // networks) it falls back to the supplied static config.
    let net = Net::dhcp_or_static(
        uni::net::Ipv4Addr::new(10, 0, 2, 15),
        uni::net::Ipv4Addr::new(10, 0, 2, 2),
        uni::net::Ipv4Addr::new(255, 255, 255, 0),
    )
    .await
    .expect("Net bring-up: both DHCP and static fallback failed");

    let backend_ip = net.gateway().0;
    let mut handles = uni::Handles::new();
    handles.keep(net);

    handles.keep_or_log(
        "udp echo :7",
        uni::runtime::udp_listen(7, |sock| async move {
            let mut buf = [0u8; 1500];
            loop {
                let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
                let _ = sock.send_to(src_ip, src_port, &buf[..n]);
            }
        }),
    );

    handles.keep_or_log(
        "tcp echo :9",
        uni::runtime::tcp_listen(9, |stream| async move {
            let mut buf = [0u8; 1024];
            loop {
                // 30 s idle timeout via `timeout_us`. On a steady
                // echo flow the recv wins every time; on an
                // abandoned connection the timer fires and we tear
                // down.
                let Some(n) = uni::runtime::timeout_us(
                    30_000_000,
                    stream.recv(&mut buf),
                ).await else { return; };
                if n == 0 { return; }
                if stream.send(&buf[..n]).await.is_err() { return; }
            }
        }),
    );

    // Gateway listener — `gateway_max` workload's server side.
    // Each accepted TCP conn opens a connected UDP flow to the
    // backend and ping-pongs:
    //   tcp_recv_exact → udp_send → udp_recv_payload → tcp_send.
    handles.keep_or_log(
        "gateway :9000",
        uni::runtime::tcp_listen(GATEWAY_PORT, move |stream| async move {
            let Ok(udp) = uni::runtime::UdpFlow::connect(
                backend_ip, GATEWAY_BACKEND_PORT,
            ) else { return; };
            let mut buf = [0u8; GATEWAY_MSG_SIZE];
            loop {
                if stream.recv_exact(&mut buf).await.is_err() { return; }
                if udp.send(&buf).is_err() { return; }
                // Zero-copy receive: the runtime hands us a borrow
                // of the inbox slot, we copy directly into the TCP
                // send buffer without a stack-buffer round-trip.
                let n = udp.recv_payload(|payload| {
                    let n = payload.len();
                    buf[..n].copy_from_slice(payload);
                    n
                }).await;
                if n != GATEWAY_MSG_SIZE { return; }
                if stream.send(&buf).await.is_err() { return; }
            }
        }),
    );

    let http_port = uni::config_port(HTTP_PORT);
    handles.keep_or_log(
        "http",
        uni_http::listen(http_port, handle_request),
    );

    // HTTPS is opt-in: if the bundled dev cert/key don't parse,
    // log + skip rather than refuse to boot.
    let https_port = uni::config_tls_port(HTTPS_PORT);
    handles.keep_or_log(
        "https",
        uni_tls::listen(https_port, handle_request, DEV_CERT_DER, DEV_KEY_PKCS8_DER),
    );

    uni::println!("Entering event loop.");
    uni::run(WebServerApp { handles });
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
    uni::println!(
        "BOOT_INFO ram={} cpus={} nics={} boot_args=\"{}\"",
        bi.ram_bytes, bi.num_cpus, bi.nics.len(), bi.boot_args,
    );
    for (i, nic) in bi.nics.iter().enumerate() {
        uni::println!(
            "BOOT_INFO nic[{}] name={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} qps={}",
            i, nic.name,
            nic.mac[0], nic.mac[1], nic.mac[2], nic.mac[3], nic.mac[4], nic.mac[5],
            nic.num_queue_pairs,
        );
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
/// the NIC is distributing flows under Tier 1 multi-queue.
fn stats_response() -> Response {
    let counts = uni::diagnostics::net_rx_counts();
    let cursors = uni::diagnostics::net_rx_used_cursors();
    let nqp = uni::diagnostics::net_num_queue_pairs() as usize;

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

    Response::ok(b"application/json", body)
}

/// Snapshot of kernel heap utilisation.
fn heap_response() -> Response {
    let s = uni::diagnostics::heap_stats();
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
    Response::ok(b"application/json", body)
}

/// TLS handshake profiler output as plain text.
const PROFILE_BUF_LEN: usize = 4096;

fn tls_profile_response() -> Response {
    let mut buf = alloc::vec![0u8; PROFILE_BUF_LEN];
    let n = uni_tls::tls_profile_report(buf.as_mut_slice());
    buf.truncate(n);
    Response::ok(b"text/plain", buf)
}
