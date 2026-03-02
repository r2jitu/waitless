// UniKernel Example: HTTP Web Server in Rust
//
// This demonstrates writing a unikernel application in Rust using #![no_std].
// The Rust code links against the C++ unikernel runtime via FFI.
// All driver and network calls are direct function calls — zero overhead.
//
// Build integration:
//   1. Compile this as a staticlib crate with target x86_64-unknown-none
//   2. Link the .a into the unikernel binary alongside the C++ runtime
//   See apps/webserver_rust/BUILD.bazel for the Bazel setup.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ffi::c_char;

// --- FFI bindings to the unikernel runtime ---

extern "C" {
    fn serial_printf(fmt: *const c_char, ...);

    // TCP interface
    fn tcp_listen(port: u16) -> *mut TcpConnection;
    fn tcp_accept(listener: *mut TcpConnection) -> *mut TcpConnection;
    fn tcp_recv(conn: *mut TcpConnection, buf: *mut u8, max_len: usize) -> usize;
    fn tcp_send(conn: *mut TcpConnection, data: *const u8, len: usize) -> i32;
    fn tcp_close(conn: *mut TcpConnection);
    fn tcp_poll();
    fn tcp_has_data(conn: *mut TcpConnection) -> bool;
}

#[repr(C)]
struct TcpConnection {
    _opaque: [u8; 0],
}

// --- Panic handler ---

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        serial_printf(b"PANIC: Rust application panicked\n\0".as_ptr() as *const c_char);
    }
    loop {
        core::hint::spin_loop();
    }
}

// --- HTTP Response Helper ---

fn send_http_response(conn: *mut TcpConnection, status: u16, content_type: &[u8], body: &[u8]) {
    // Build response in a stack buffer
    let mut buf = [0u8; 4096];
    let mut pos = 0;

    let status_line = match status {
        200 => b"HTTP/1.1 200 OK\r\n",
        404 => b"HTTP/1.1 404 Not Found\r\n",
        _ => b"HTTP/1.1 500 Internal Server Error\r\n",
    };

    // Copy status line
    let n = status_line.len();
    buf[pos..pos + n].copy_from_slice(status_line);
    pos += n;

    // Content-Type header
    let ct_prefix = b"Content-Type: ";
    buf[pos..pos + ct_prefix.len()].copy_from_slice(ct_prefix);
    pos += ct_prefix.len();
    buf[pos..pos + content_type.len()].copy_from_slice(content_type);
    pos += content_type.len();
    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos += 2;

    // Content-Length header
    let cl_prefix = b"Content-Length: ";
    buf[pos..pos + cl_prefix.len()].copy_from_slice(cl_prefix);
    pos += cl_prefix.len();

    // Simple integer to string for body length
    let mut len_buf = [0u8; 20];
    let len_str = format_usize(body.len(), &mut len_buf);
    buf[pos..pos + len_str.len()].copy_from_slice(len_str);
    pos += len_str.len();
    buf[pos..pos + 2].copy_from_slice(b"\r\n");
    pos += 2;

    // Connection: close
    let close_hdr = b"Connection: close\r\n\r\n";
    buf[pos..pos + close_hdr.len()].copy_from_slice(close_hdr);
    pos += close_hdr.len();

    // Body
    let body_end = if pos + body.len() <= buf.len() {
        buf[pos..pos + body.len()].copy_from_slice(body);
        pos + body.len()
    } else {
        let fit = buf.len() - pos;
        buf[pos..pos + fit].copy_from_slice(&body[..fit]);
        pos + fit
    };

    unsafe {
        tcp_send(conn, buf.as_ptr(), body_end);
    }
}

fn format_usize(mut n: usize, buf: &mut [u8; 20]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut pos = 20;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[pos..]
}

// --- Application Entry Point ---

#[no_mangle]
pub extern "C" fn uni_main() -> i32 {
    unsafe {
        serial_printf(b"Rust HTTP server starting on port 80...\n\0".as_ptr() as *const c_char);
    }

    let listener = unsafe { tcp_listen(80) };
    if listener.is_null() {
        unsafe {
            serial_printf(b"Failed to create TCP listener\n\0".as_ptr() as *const c_char);
        }
        return 1;
    }

    let mut recv_buf = [0u8; 4096];

    loop {
        unsafe { tcp_poll() };

        let conn = unsafe { tcp_accept(listener) };
        if conn.is_null() {
            continue;
        }

        // Wait for data
        if !unsafe { tcp_has_data(conn) } {
            continue;
        }

        let n = unsafe { tcp_recv(conn, recv_buf.as_mut_ptr(), recv_buf.len()) };
        if n == 0 {
            unsafe { tcp_close(conn) };
            continue;
        }

        // Simple routing: check if request starts with "GET / "
        let is_index = n >= 6
            && recv_buf[0] == b'G'
            && recv_buf[1] == b'E'
            && recv_buf[2] == b'T'
            && recv_buf[3] == b' '
            && recv_buf[4] == b'/'
            && recv_buf[5] == b' ';

        let is_health = n >= 12 && &recv_buf[4..11] == b"/health";

        if is_index {
            send_http_response(
                conn,
                200,
                b"application/json",
                b"{\"message\":\"Hello from Rust UniKernel!\",\"runtime\":\"unikernel\",\"lang\":\"rust\"}",
            );
        } else if is_health {
            send_http_response(
                conn,
                200,
                b"application/json",
                b"{\"status\":\"ok\"}",
            );
        } else {
            send_http_response(
                conn,
                404,
                b"text/plain",
                b"Not Found",
            );
        }

        unsafe { tcp_close(conn) };
    }
}
