// UniKernel Example: HTTP Web Server
//
// Pure application logic. #[uni::main] handles the platform entry point.

#![no_std]

extern crate uni;
use core::cell::UnsafeCell;
use uni::http::{Request, Response, Server, TlsServerConfig};

// Checked-in self-signed ECDSA P-256 dev cert + private key, baked
// into the binary via include_bytes!. See `apps/webserver/dev_certs/README.md`
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

// ---- /tls_profile scratch buffers -----------------------------------------
//
// The TLS handshake profiler (in `//net:tls_server`) accumulates
// per-stage timings across every handshake; the `/tls_profile`
// endpoint renders those totals as plain text. `Response` just
// carries raw byte pointers, so the formatter needs a backing buffer
// that outlives the handler return. We use one 4 KB buffer per core,
// indexed by `uni::cpu_id()`, so two handlers on different cores can
// render reports concurrently without racing on the same scratch.
// Within a single core, `service_core` runs the handler and
// `send_response` back-to-back, so the buffer only needs to survive
// until the bytes hit the TX path — exactly what a per-core slot
// gives us.
const MAX_CORES: usize = 8;
const PROFILE_BUF_LEN: usize = 4096;
struct ProfileSlot(UnsafeCell<[u8; PROFILE_BUF_LEN]>);
unsafe impl Sync for ProfileSlot {}
static PROFILE_BUFS: [ProfileSlot; MAX_CORES] = [
    ProfileSlot(UnsafeCell::new([0u8; PROFILE_BUF_LEN])),
    ProfileSlot(UnsafeCell::new([0u8; PROFILE_BUF_LEN])),
    ProfileSlot(UnsafeCell::new([0u8; PROFILE_BUF_LEN])),
    ProfileSlot(UnsafeCell::new([0u8; PROFILE_BUF_LEN])),
    ProfileSlot(UnsafeCell::new([0u8; PROFILE_BUF_LEN])),
    ProfileSlot(UnsafeCell::new([0u8; PROFILE_BUF_LEN])),
    ProfileSlot(UnsafeCell::new([0u8; PROFILE_BUF_LEN])),
    ProfileSlot(UnsafeCell::new([0u8; PROFILE_BUF_LEN])),
];

fn tls_profile_response() -> Response {
    let id = (uni::cpu_id() as usize) % MAX_CORES;
    // SAFETY: each core uses its own slot (indexed by cpu_id), and
    // service_core runs the handler + send_response back-to-back on
    // one core without yielding, so no concurrent aliasing is
    // possible. The raw pointer stored in `Response` points into
    // this same slot for exactly that duration.
    let buf: &mut [u8; PROFILE_BUF_LEN] = unsafe { &mut *PROFILE_BUFS[id].0.get() };
    let n = uni::http::tls_profile_report(buf);
    Response::ok(b"text/plain", &buf[..n])
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
        b"/tls_profile" => tls_profile_response(),
        b"/tls_profile_reset" => {
            uni::http::tls_profile_reset();
            Response::ok(b"text/plain", b"tls profile reset\n")
        }
        _ => Response::not_found(),
    }
}


// ---- Application entry point ------------------------------------------------

/// Plain HTTP listener port. `uni::config_port` lets the runner
/// override this via env var (e.g. for per-test fixtures); we pass
/// 80 as the default.
const HTTP_PORT: u16 = 80;

/// HTTPS listener port. Runs alongside HTTP so apps can be reached
/// over both protocols with the same routes. The HVF runner / QEMU
/// user-mode networking forward a host port to this one for local
/// testing (conventionally 8080 → :80 and 8443 → :443).
const HTTPS_PORT: u16 = 443;

#[uni::main]
fn main() {
    uni::log(b"Starting Rust HTTP server...\n");
    let http_port = uni::config_port(HTTP_PORT);

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

    // Plain HTTP is always on.
    server.listen(http_port);

    // HTTPS is added alongside when the dev cert parses. The same
    // routes serve both listeners — handlers don't care whether a
    // given request arrived over TLS or not.
    match TlsServerConfig::from_dev_cert(DEV_CERT_DER, DEV_KEY_PKCS8_DER) {
        Some(cfg) => {
            let config: &'static TlsServerConfig =
                uni::Box::leak(uni::Box::new(cfg));
            uni::log(b"TLS: dev cert loaded. Serving HTTPS.\n");
            server.listen_tls(HTTPS_PORT, config);
        }
        None => {
            uni::log(b"TLS: failed to parse dev key; HTTPS disabled.\n");
        }
    }

    uni::log(b"Entering event loop.\n");
    server.run();
}
