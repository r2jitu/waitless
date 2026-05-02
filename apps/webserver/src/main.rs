// UniKernel Example: HTTP Web Server
//
// `#[uni::init]` is the entry point. The macro spawns the body as
// a task; once it returns, listeners (registered via the `listen`
// helpers) keep running for the lifetime of the process. Shutdown
// (SIGINT / serial Ctrl-C) tears every retained listener down and
// drops the network stack symmetrically.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;

use uni::net::Net;
use uni::runtime::{TcpStream, UdpClient};
use uni_http::{Request, Response};

// ---- Configuration ----------------------------------------------------------

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;
const GATEWAY_PORT: u16 = 9000;
const GATEWAY_BACKEND_PORT: u16 = 7777;
const GATEWAY_MSG_SIZE: usize = 32;

// Self-signed dev cert + key (ECDSA P-256 + SHA-256). Regen via
// `apps/webserver/dev_certs/regen.sh`. NOT FOR PRODUCTION.
const DEV_CERT_DER: &[u8] = include_bytes!("../dev_certs/dev_cert.der");
const DEV_KEY_PKCS8_DER: &[u8] = include_bytes!("../dev_certs/dev_key.der");

// ---- Boot -------------------------------------------------------------------

#[uni::init]
async fn init() {
    log_boot_info();

    // VM-friendly bring-up: DHCP first, fall back to NAT-default
    // static (10.0.2.15/24, gw 10.0.2.2). For dedicated NICs / non-
    // NAT environments use `Net::dhcp_or_static(...)` with explicit
    // values.
    let net = Net::up().await.expect("Net::up failed");
    let backend_ip = net.gateway().0;

    uni::udp_listen(7, udp_echo).expect("udp echo bind");
    uni::tcp_listen(9, tcp_echo).expect("tcp echo bind");
    uni::tcp_listen(GATEWAY_PORT, move |s| gateway(s, backend_ip))
        .expect("gateway bind");
    uni_http::listen(HTTP_PORT, handle_request).expect("http bind");

    // HTTPS is opt-in: if the bundled dev cert/key don't parse,
    // log + skip rather than refuse to boot.
    match uni_tls::listen(HTTPS_PORT, handle_request, DEV_CERT_DER, DEV_KEY_PKCS8_DER) {
        Ok(()) => uni::println!("HTTPS enabled"),
        Err(_) => uni::println!("HTTPS disabled (cert/key invalid)"),
    }
}

// ---- Listener bodies --------------------------------------------------------

async fn udp_echo(sock: alloc::sync::Arc<uni::runtime::UdpSocket>) {
    let mut buf = [0u8; 1500];
    loop {
        let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
        let _ = sock.send_to(src_ip, src_port, &buf[..n]);
    }
}

async fn tcp_echo(stream: TcpStream) {
    let mut buf = [0u8; 1024];
    loop {
        // 30 s idle timeout. Steady echo flow always wins; an
        // abandoned connection lets the timer fire and we tear
        // down rather than leak the slot.
        let Some(n) = uni::runtime::timeout_us(30_000_000, stream.recv(&mut buf)).await
        else { return; };
        if n == 0 { return; }
        if stream.send(&buf[..n]).await.is_err() { return; }
    }
}

/// Gateway handler — `gateway_max` workload's server side. Each
/// accepted TCP conn opens a connected UDP flow to the backend and
/// ping-pongs:
///   tcp_recv_exact → udp.send → udp.recv_into → tcp_send.
async fn gateway(stream: TcpStream, backend_ip: [u8; 4]) {
    let Ok(udp) = UdpClient::connect(backend_ip, GATEWAY_BACKEND_PORT) else { return; };
    let mut buf = [0u8; GATEWAY_MSG_SIZE];
    loop {
        if stream.recv_exact(&mut buf).await.is_err() { return; }
        if udp.send(&buf).is_err() { return; }
        if udp.recv(&mut buf).await != GATEWAY_MSG_SIZE { return; }
        if stream.send(&buf).await.is_err() { return; }
    }
}

// ---- Request dispatch + route handlers --------------------------------------

async fn handle_request(req: &Request) -> Response {
    match req.path() {
        b"/"        => Response::ok(b"text/html", INDEX_HTML),
        b"/health"  => Response::ok(b"application/json", HEALTH_JSON),
        b"/stats"   => stats_response(),
        b"/heap"    => heap_response(),
        b"/compute" => {
            // black_box prevents the compiler from eliminating compute_work
            // as dead code (the return value would otherwise be unused).
            core::hint::black_box(compute_work());
            Response::ok(b"application/json", b"{\"status\":\"computed\"}")
        }
        b"/tls_profile"       => tls_profile_response(),
        b"/tls_profile_reset" => {
            uni_tls::tls_profile_reset();
            Response::ok(b"text/plain", b"tls profile reset\n")
        }
        _ => Response::not_found(),
    }
}

/// Emit the contents of `uni::boot_info()` at startup. Line tags
/// (`BOOT_INFO ram=...`) are stable so the integration test can
/// grep them out of the serial log.
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
<h2>Endpoints</h2>\
<ul>\
<li><a href='/'>/ </a> \xe2\x80\x94 this page</li>\
<li><a href='/health'>/health</a> \xe2\x80\x94 health check (JSON)</li>\
<li><a href='/stats'>/stats</a> \xe2\x80\x94 runtime statistics</li>\
</ul>\
<p><small>UniKernel v0.1.0</small></p>\
</body></html>";

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
