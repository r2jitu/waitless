// UniKernel Example: HTTP Web Server
//
// Pure application logic. #[uni::main] handles the platform entry point.

#![no_std]

extern crate uni;
use uni::http::{Request, Response, Server, TlsServerConfig};

// Checked-in self-signed Ed25519 dev cert + private key, baked into
// the binary via include_bytes!. See `apps/webserver/dev_certs/README.md`
// for details and the regen.sh script. DO NOT USE IN PRODUCTION.
const DEV_CERT_DER: &[u8] = include_bytes!("dev_certs/dev_cert.der");
const DEV_KEY_PKCS8_DER: &[u8] = include_bytes!("dev_certs/dev_key.der");

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

/// CPU-intensive work: iterative hash (FNV-1a, 100K iterations).
/// Dominates per-request cost, making multi-core distribution visible.
fn compute_work() -> u32 {
    let mut h: u32 = 2166136261;
    for i in 0..100_000u32 {
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
            // black_box prevents the compiler from eliminating compute_work()
            // as dead code (the return value would otherwise be unused).
            core::hint::black_box(compute_work());
            Response::ok(b"application/json", b"{\"status\":\"computed\"}")
        }
        _ => Response::not_found(),
    }
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

    // Allocate the Server (and its per-connection buffers) on the heap.
    // `Box::leak` extends the lifetime to 'static so worker threads and AP
    // service callbacks can keep accessing it via SERVER_PTR after main()
    // returns on native (on unikernel `run()` blocks forever).
    let server: &'static mut Server = uni::Box::leak(Server::new_boxed());
    server.default_handler(handle_request);

    // Parse the checked-in dev cert + Ed25519 key once at boot. On
    // the unikernel platform this gives us a valid TlsServerConfig;
    // on native it's a stub, and `run_tls()` falls back to plain HTTP.
    let config: &'static TlsServerConfig = match TlsServerConfig::from_dev_cert(
        DEV_CERT_DER,
        DEV_KEY_PKCS8_DER,
    ) {
        Some(cfg) => uni::Box::leak(uni::Box::new(cfg)),
        None => {
            uni::log(b"TLS: failed to parse dev key; serving plain HTTP.\n");
            server.run(port);
            return;
        }
    };
    uni::log(b"TLS: dev cert loaded. Serving HTTPS.\n");
    server.run_tls(port, config);
}
