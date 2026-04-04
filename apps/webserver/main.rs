// UniKernel Example: HTTP Web Server in Rust
//
// Equivalent to the C++ webserver (main.cc), running on the same bare-metal
// unikernel runtime. Uses the C++ HTTP server via FFI dispatch callback.
// All driver and network calls are direct function calls — zero overhead.

#![no_std]
#![no_main]

use core::ffi::c_char;
use core::panic::PanicInfo;

// ---- FFI bindings to the C++ runtime ----------------------------------------

#[repr(C)]
struct FfiHttpResponse {
    status: i32,
    content_type: *const c_char,
    body: *const c_char,
    body_len: u64,
}

type FfiHttpDispatch = unsafe extern "C" fn(*const c_char, i32) -> FfiHttpResponse;

unsafe extern "C" {
    fn uni_log(msg: *const c_char);
    fn uni_config_port(default_port: u16) -> u16;
    fn http_server_set_dispatch(dispatch: FfiHttpDispatch);
    fn http_server_run(port: u16);
}

// ---- Panic handler ----------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        uni_log(b"PANIC: Rust webserver panicked!\n\0".as_ptr() as *const c_char);
    }
    loop {
        core::hint::spin_loop();
    }
}

// Stub for macOS host core library (compiled with panic=unwind, references this symbol).
// On bare-metal targets (panic=abort), core doesn't reference it.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

// ---- Response helpers -------------------------------------------------------

const fn ok(content_type: &'static [u8], body: &'static [u8]) -> FfiHttpResponse {
    FfiHttpResponse {
        status: 200,
        content_type: content_type.as_ptr() as *const c_char,
        body: body.as_ptr() as *const c_char,
        body_len: body.len() as u64,
    }
}

const fn not_found() -> FfiHttpResponse {
    FfiHttpResponse {
        status: 404,
        content_type: b"text/plain\0".as_ptr() as *const c_char,
        body: b"404 Not Found\0".as_ptr() as *const c_char,
        body_len: 13,
    }
}

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
HTTP parser (net::http)\n\
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

// ---- Dispatch function ------------------------------------------------------

/// Compares a null-terminated C string with a Rust byte slice (without null).
unsafe fn path_eq(c_path: *const c_char, expected: &[u8]) -> bool {
    let c = c_path as *const u8;
    for (i, &b) in expected.iter().enumerate() {
        if unsafe { *c.add(i) } != b {
            return false;
        }
    }
    // Ensure C string ends here (null terminator)
    unsafe { *c.add(expected.len()) == 0 }
}

/// HTTP request dispatch — called by the C++ HTTP server for every request.
unsafe extern "C" fn dispatch(path: *const c_char, _method: i32) -> FfiHttpResponse {
    if unsafe { path_eq(path, b"/") } {
        ok(b"text/html\0", INDEX_HTML)
    } else if unsafe { path_eq(path, b"/health") } {
        ok(b"application/json\0", HEALTH_JSON)
    } else if unsafe { path_eq(path, b"/stats") } {
        ok(b"application/json\0", STATS_JSON)
    } else {
        not_found()
    }
}

// ---- Application entry point ------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn uni_main() -> i32 {
    unsafe {
        uni_log(b"Starting Rust HTTP server...\n\0".as_ptr() as *const c_char);
        http_server_set_dispatch(dispatch);
        uni_log(b"Routes registered. Entering event loop.\n\0".as_ptr() as *const c_char);
        let port = uni_config_port(80);
        http_server_run(port);
        uni_log(b"[uni_main] server.run() returned -- shutting down\n\0".as_ptr() as *const c_char);
    }
    0
}
