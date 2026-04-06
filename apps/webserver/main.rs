// UniKernel Example: HTTP Web Server
//
// Pure application logic. #[uni::main] handles the platform entry point.

#![no_std]

extern crate uni;
use uni::http::{Request, Response, Server};

// ---- Request handlers -------------------------------------------------------

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
HTTP parser (Rust)\n\
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
<p><small>Built with UniKernel v0.1.0 (Rust)</small></p>\
</body></html>";

const HEALTH_JSON: &[u8] = b"{\"status\":\"ok\",\"runtime\":\"unikernel\",\"version\":\"0.1.0\"}";

const STATS_JSON: &[u8] =
    b"{\"connections_active\":0,\"total_requests\":0,\"memory_free_mb\":0,\"uptime_seconds\":0}";

/// CPU-intensive work: iterative hash (FNV-1a, 10K iterations).
/// Takes ~50-100us under TCG, making it the dominant cost per request.
fn compute_work() -> u32 {
    let mut h: u32 = 2166136261;
    for i in 0..10_000u32 {
        h ^= i;
        h = h.wrapping_mul(16777619);
    }
    h
}

fn handle_request(req: &Request) -> Response {
    match req.path() {
        b"/" => Response::ok(b"text/html", INDEX_HTML),
        b"/health" => Response::ok(b"application/json", HEALTH_JSON),
        b"/stats" => Response::ok(b"application/json", STATS_JSON),
        b"/compute" => {
            let result = compute_work();
            // Format result as JSON into a stack buffer
            let mut buf = [0u8; 64];
            let mut pos = 0;
            for &b in b"{\"hash\":" { buf[pos] = b; pos += 1; }
            pos += fmt_u32(&mut buf[pos..], result);
            for &b in b"}" { buf[pos] = b; pos += 1; }
            Response::ok(b"application/json", &buf[..pos])
        }
        _ => Response::not_found(),
    }
}

fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 { tmp[len] = b'0' + (val % 10) as u8; val /= 10; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}

// ---- Application entry point ------------------------------------------------

#[uni::main]
fn main() {
    uni::log(b"Starting Rust HTTP server...\n");
    let port = uni::config_port(80);

    // Start UDP echo server on port 7
    fn udp_echo(src_ip: [u8; 4], src_port: u16, data: &[u8]) {
        uni::udp_send(src_ip, 7, src_port, data);
    }
    uni::udp_bind(7, udp_echo);
    uni::log(b"UDP echo server on port 7\n");

    static mut SERVER: Server = Server::new();
    let server = unsafe { &mut *core::ptr::addr_of_mut!(SERVER) };
    server.default_handler(handle_request);

    uni::log(b"Routes registered. Entering event loop.\n");
    server.run(port);
}
