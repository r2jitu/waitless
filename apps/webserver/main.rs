// UniKernel Example: HTTP Web Server in Rust
//
// Runs on the bare-metal unikernel runtime with a pure Rust HTTP server.
// All driver and network calls are direct function calls — zero overhead.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use http::{Request, Response, Server};

extern crate uni;

// ---- Panic handler ----------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uni::log(b"PANIC: Rust webserver panicked!\n\0");
    loop {
        core::hint::spin_loop();
    }
}

// Stub for macOS host core library (compiled with panic=unwind, references this symbol).
// On bare-metal targets (panic=abort), core doesn't reference it.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

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

fn handle_request(req: &Request) -> Response {
    match req.path() {
        b"/" => Response::ok(b"text/html", INDEX_HTML),
        b"/health" => Response::ok(b"application/json", HEALTH_JSON),
        b"/stats" => Response::ok(b"application/json", STATS_JSON),
        _ => Response::not_found(),
    }
}

// ---- Application entry point ------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn uni_main() -> i32 {
    uni::log(b"Starting Rust HTTP server...\n\0");
    let port = uni::config_port(80);

    static mut SERVER: Server = Server::new();
    // Safety: uni_main is single-threaded and called exactly once.
    let server = unsafe { &mut *core::ptr::addr_of_mut!(SERVER) };
    server.default_handler(handle_request);

    uni::log(b"Routes registered. Entering event loop.\n\0");
    server.run(port);
    uni::log(b"[uni_main] server.run() returned -- shutting down\n\0");
    0
}
