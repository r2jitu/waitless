// uni/http.rs — HTTP/1.1 server library (pure Rust, no_std)
//
// Non-blocking cooperative model: Server::run() polls the network stack,
// accepts connections, reads data, parses HTTP requests, dispatches to
// handlers, and sends responses.
//
// Multi-core: each core creates its own TCP listener and maintains its
// own active connection set. Core 0 runs the main event loop; APs run
// HTTP service via the percpu ap_poll hook. Routes are shared (read-only).
//
// All buffers are fixed-size, stack/static allocated. No heap.

use crate::{TcpListener, TcpStream};

// ---- HTTP types -------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Method {
    Get = 0,
    Post = 1,
    Put = 2,
    Delete = 3,
    Head = 4,
    Unknown = 5,
}

pub struct Header {
    name: [u8; 64],
    name_len: usize,
    value: [u8; 256],
    value_len: usize,
}

impl Header {
    const fn new() -> Self {
        Header {
            name: [0; 64],
            name_len: 0,
            value: [0; 256],
            value_len: 0,
        }
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

pub struct Request {
    pub method: Method,
    path: [u8; 256],
    path_len: usize,
    headers: [Header; 16],
    header_count: usize,
    body: [u8; 8192],
    body_len: usize,
}

impl Request {
    pub fn new() -> Self {
        Request {
            method: Method::Unknown,
            path: [0; 256],
            path_len: 0,
            headers: [const { Header::new() }; 16],
            header_count: 0,
            body: [0; 8192],
            body_len: 0,
        }
    }

    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    pub fn get_header(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.header_count {
            if self.headers[i].name().eq_ignore_ascii_case(name) {
                return Some(self.headers[i].value());
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn body(&self) -> &[u8] {
        &self.body[..self.body_len]
    }

    fn clear(&mut self) {
        self.method = Method::Unknown;
        self.path_len = 0;
        self.header_count = 0;
        self.body_len = 0;
    }
}

// ---- Response ---------------------------------------------------------------

pub struct Response {
    pub status: i32,
    content_type: [u8; 64],
    content_type_len: usize,
    body: [u8; 8192],
    body_len: usize,
}

impl Response {
    pub fn ok(content_type: &[u8], body: &[u8]) -> Self {
        let mut resp = Response {
            status: 200,
            content_type: [0; 64],
            content_type_len: 0,
            body: [0; 8192],
            body_len: 0,
        };
        let ct = content_type.len().min(64);
        resp.content_type[..ct].copy_from_slice(&content_type[..ct]);
        resp.content_type_len = ct;
        let bl = body.len().min(8192);
        resp.body[..bl].copy_from_slice(&body[..bl]);
        resp.body_len = bl;
        resp
    }

    pub fn not_found() -> Self {
        let mut resp = Self::ok(b"text/plain", b"Not Found");
        resp.status = 404;
        resp
    }

    fn body_bytes(&self) -> &[u8] {
        &self.body[..self.body_len]
    }
    fn content_type_bytes(&self) -> &[u8] {
        &self.content_type[..self.content_type_len]
    }
}

// ---- Handler type -----------------------------------------------------------

pub type Handler = fn(&Request) -> Response;

// ---- Server -----------------------------------------------------------------

const MAX_ROUTES: usize = 64;
const MAX_ACTIVE: usize = 16; // per core
const BUF_SIZE: usize = 8192;
const MAX_CORES: usize = 8;

struct Route {
    path: [u8; 256],
    path_len: usize,
    handler: Option<Handler>,
}

impl Route {
    const fn new() -> Self {
        Route {
            path: [0; 256],
            path_len: 0,
            handler: None,
        }
    }
}

struct ActiveConn {
    conn: Option<TcpStream>,
    buf: [u8; BUF_SIZE],
    buf_len: usize,
}

impl ActiveConn {
    const fn new() -> Self {
        ActiveConn {
            conn: None,
            buf: [0; BUF_SIZE],
            buf_len: 0,
        }
    }
}

/// Per-core HTTP state: listener + active connections.
struct CoreHttp {
    listener: Option<TcpListener>,
    active: [ActiveConn; MAX_ACTIVE],
}

impl CoreHttp {
    const fn new() -> Self {
        CoreHttp {
            listener: None,
            active: [const { ActiveConn::new() }; MAX_ACTIVE],
        }
    }
}

pub struct Server {
    routes: [Route; MAX_ROUTES],
    route_count: usize,
    default_handler: Option<Handler>,
    cores: [CoreHttp; MAX_CORES],
}

// Global server pointer for AP poll callback.
static mut SERVER_PTR: *mut Server = core::ptr::null_mut();

impl Server {
    pub const fn new() -> Self {
        Server {
            routes: [const { Route::new() }; MAX_ROUTES],
            route_count: 0,
            default_handler: None,
            cores: [const { CoreHttp::new() }; MAX_CORES],
        }
    }

    /// Register an exact-path handler.
    pub fn route(&mut self, path: &[u8], handler: Handler) {
        if self.route_count >= MAX_ROUTES {
            crate::log(b"http: too many routes\n");
            return;
        }
        let r = &mut self.routes[self.route_count];
        let len = path.len().min(255);
        r.path[..len].copy_from_slice(&path[..len]);
        r.path_len = len;
        r.handler = Some(handler);
        self.route_count += 1;
    }

    /// Set the fallback handler (called when no route matches).
    pub fn default_handler(&mut self, handler: Handler) {
        self.default_handler = Some(handler);
    }

    /// Run the event loop. Blocks until shutdown signal.
    pub fn run(&mut self, port: u16) {
        // Create a listener on each core's TCP pool (SO_REUSEPORT pattern).
        // SYN packets hashed to core N will find the listener in core N's pool.
        #[cfg(platform_unikernel)]
        let num_cores = kernel::percpu::num_cores();
        #[cfg(not(platform_unikernel))]
        let num_cores = 1u32;

        for i in 0..num_cores {
            #[cfg(platform_unikernel)]
            let handle = net::tcp::listen_on_core(i, port);
            #[cfg(not(platform_unikernel))]
            let handle = crate::backend::tcp_listen(port);

            if handle.is_null() {
                crate::log(b"http: failed to create TCP listener\n");
                if i == 0 { return; }
            } else {
                self.cores[i as usize].listener = Some(TcpListener(handle));
            }
        }

        // Register AP poll hook for multi-core HTTP service.
        #[cfg(platform_unikernel)]
        if num_cores > 1 {
            unsafe { SERVER_PTR = self as *mut Server; }
            kernel::percpu::set_ap_poll_fn(ap_http_poll);
        }

        crate::log(b"http: listening\n");

        loop {
            if crate::check_shutdown() {
                crate::log(b"http: shutdown requested\n");
                break;
            }
            crate::tcp_poll();

            let had_work = self.service_core(0);

            if !had_work {
                crate::wait_for_events();
            }
        }

        // Graceful shutdown
        for core in self.cores.iter_mut() {
            for ac in core.active.iter_mut() {
                if let Some(conn) = ac.conn.take() {
                    conn.close();
                    ac.buf_len = 0;
                }
            }
            if let Some(l) = core.listener.take() {
                l.close();
            }
        }
        crate::log(b"http: server stopped\n");
    }

    /// Service connections for a specific core. Returns true if any work was done.
    fn service_core(&mut self, core_id: u32) -> bool {
        let mut had_work = false;

        // Accept new connections
        if let Some(listener) = self.cores[core_id as usize].listener {
            while let Some(stream) = listener.accept() {
                had_work = true;
                if let Some(ac) = alloc_active(&mut self.cores[core_id as usize].active) {
                    ac.conn = Some(stream);
                } else {
                    crate::log(b"http: too many connections, dropping\n");
                    stream.close();
                    break;
                }
            }
        }

        // Service active connections.
        // Use index-based access to avoid borrow conflicts with find_handler.
        for i in 0..MAX_ACTIVE {
            let conn = match self.cores[core_id as usize].active[i].conn {
                Some(c) => c,
                None => continue,
            };

            if conn.is_closed() {
                self.cores[core_id as usize].active[i].conn = None;
                self.cores[core_id as usize].active[i].buf_len = 0;
                had_work = true;
                continue;
            }

            if conn.has_data() {
                let buf_len = self.cores[core_id as usize].active[i].buf_len;
                let avail = BUF_SIZE - buf_len;
                if avail > 0 {
                    let got = conn.recv(&mut self.cores[core_id as usize].active[i].buf[buf_len..buf_len + avail]);
                    self.cores[core_id as usize].active[i].buf_len += got;
                    had_work = true;
                }
            }

            let buf_len = self.cores[core_id as usize].active[i].buf_len;
            if buf_len > 0 {
                let mut req = Request::new();
                let consumed = parse_request(&self.cores[core_id as usize].active[i].buf[..buf_len], &mut req);
                if consumed > 0 {
                    let want_close = match req.get_header(b"Connection") {
                        Some(v) => v.eq_ignore_ascii_case(b"close"),
                        None => false,
                    };

                    let handler = self.find_handler(req.path());
                    let resp = match handler {
                        Some(h) => h(&req),
                        None => Response::not_found(),
                    };

                    send_response(conn, &resp, !want_close);
                    had_work = true;

                    if want_close {
                        conn.close();
                        self.cores[core_id as usize].active[i].conn = None;
                        self.cores[core_id as usize].active[i].buf_len = 0;
                    } else {
                        let remaining = buf_len - consumed;
                        if remaining > 0 {
                            self.cores[core_id as usize].active[i].buf.copy_within(consumed..buf_len, 0);
                        }
                        self.cores[core_id as usize].active[i].buf_len = remaining;
                    }
                } else if buf_len >= BUF_SIZE {
                    conn.close();
                    self.cores[core_id as usize].active[i].conn = None;
                    self.cores[core_id as usize].active[i].buf_len = 0;
                }
            }
        }

        had_work
    }

    fn find_handler(&self, path: &[u8]) -> Option<Handler> {
        let routes = &self.routes[..self.route_count];
        // Exact match first
        if let Some(r) = routes.iter().find(|r| r.path[..r.path_len] == *path) {
            return r.handler;
        }
        // Prefix match (e.g. "/api" matches "/api/v1/foo")
        if let Some(r) = routes.iter().find(|r| {
            r.path_len > 1 && path.len() >= r.path_len
                && r.path[..r.path_len] == path[..r.path_len]
        }) {
            return r.handler;
        }
        self.default_handler
    }
}

fn alloc_active(active: &mut [ActiveConn; MAX_ACTIVE]) -> Option<&mut ActiveConn> {
    for ac in active.iter_mut() {
        if ac.conn.is_none() {
            ac.buf_len = 0;
            return Some(ac);
        }
    }
    None
}

/// AP poll callback: drain RX inbox (network packets), then service HTTP connections.
fn ap_http_poll(core_id: u32) -> bool {
    // First, process any packets in this core's RX inbox (same as net::ap_poll).
    #[cfg(platform_unikernel)]
    {
        unsafe {
            let core = kernel::percpu::get(core_id);
            while let Some(frame) = core.rx_inbox.pop() {
                net::net_receive(frame);
            }
        }
    }

    // Then service HTTP connections.
    let server = unsafe {
        if SERVER_PTR.is_null() { return false; }
        &mut *SERVER_PTR
    };
    server.service_core(core_id)
}

// ---- HTTP request parser ----------------------------------------------------

/// Parse an HTTP request from `data`. Returns bytes consumed (>0) on success,
/// 0 if the request is incomplete.
fn parse_request(data: &[u8], req: &mut Request) -> usize {
    req.clear();

    // Find end of headers ("\r\n\r\n")
    let header_end = find_header_end(data);
    if header_end.is_none() {
        return 0;
    }
    let header_end_pos = header_end.unwrap();

    // Parse request line: "METHOD /path HTTP/1.x\r\n"
    let mut pos = 0;

    if data[pos..].starts_with(b"GET ") {
        req.method = Method::Get;
        pos += 4;
    } else if data[pos..].starts_with(b"POST ") {
        req.method = Method::Post;
        pos += 5;
    } else if data[pos..].starts_with(b"PUT ") {
        req.method = Method::Put;
        pos += 4;
    } else if data[pos..].starts_with(b"DELETE ") {
        req.method = Method::Delete;
        pos += 7;
    } else if data[pos..].starts_with(b"HEAD ") {
        req.method = Method::Head;
        pos += 5;
    } else {
        req.method = Method::Unknown;
    }

    // Extract path
    let mut path_len = 0;
    while pos < data.len()
        && data[pos] != b' '
        && data[pos] != b'\r'
        && data[pos] != b'\n'
        && path_len < 255
    {
        req.path[path_len] = data[pos];
        path_len += 1;
        pos += 1;
    }
    req.path_len = path_len;

    // Skip to end of request line
    while pos < data.len() && data[pos] != b'\n' {
        pos += 1;
    }
    if pos < data.len() {
        pos += 1; // skip \n
    }

    // Parse headers
    while pos < header_end_pos {
        if data[pos] == b'\r' || data[pos] == b'\n' {
            break;
        }

        if req.header_count < 16 {
            let h = &mut req.headers[req.header_count];

            // Header name (up to ':')
            let mut ni = 0;
            while pos < data.len() && data[pos] != b':' && data[pos] != b'\r' && ni < 63 {
                h.name[ni] = data[pos];
                ni += 1;
                pos += 1;
            }
            h.name_len = ni;

            // Skip ':' and spaces
            while pos < data.len() && (data[pos] == b':' || data[pos] == b' ') {
                pos += 1;
            }

            // Header value
            let mut vi = 0;
            while pos < data.len() && data[pos] != b'\r' && data[pos] != b'\n' && vi < 255 {
                h.value[vi] = data[pos];
                vi += 1;
                pos += 1;
            }
            h.value_len = vi;

            req.header_count += 1;
        }

        // Skip to next line
        while pos < data.len() && data[pos] != b'\n' {
            pos += 1;
        }
        if pos < data.len() {
            pos += 1;
        }
    }

    let body_start = header_end_pos + 4; // skip \r\n\r\n
    let mut consumed = body_start;

    // Handle Content-Length
    if let Some(cl_val) = req.get_header(b"Content-Length") {
        let body_len = parse_usize(cl_val);
        let avail = data.len() - body_start;
        if avail < body_len {
            return 0; // incomplete body
        }
        let copy_len = body_len.min(8191);
        req.body[..copy_len].copy_from_slice(&data[body_start..body_start + copy_len]);
        req.body_len = copy_len;
        consumed += body_len;
    }

    consumed
}

// ---- Response sender --------------------------------------------------------

struct BufWriter {
    buf: [u8; 2048],
    pos: usize,
}

impl BufWriter {
    fn new() -> Self {
        BufWriter { buf: [0u8; 2048], pos: 0 }
    }

    fn push(&mut self, data: &[u8]) {
        let n = data.len().min(2048 - self.pos);
        self.buf[self.pos..self.pos + n].copy_from_slice(&data[..n]);
        self.pos += n;
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

impl core::fmt::Write for BufWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}

fn send_response(conn: TcpStream, resp: &Response, keep_alive: bool) {
    use core::fmt::Write;

    let body = resp.body_bytes();
    let content_type = resp.content_type_bytes();
    let conn_header = if keep_alive { "keep-alive" } else { "close" };

    let mut w = BufWriter::new();
    let _ = write!(w, "HTTP/1.1 {} {}\r\n", resp.status, status_text(resp.status));
    let _ = write!(w, "Content-Type: ");
    w.push(content_type);
    let _ = write!(w, "\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n", body.len(), conn_header);
    w.push(body);

    conn.send(w.as_bytes());
}

// ---- Helper functions -------------------------------------------------------

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
}


fn parse_usize(data: &[u8]) -> usize {
    let mut n: usize = 0;
    for &b in data {
        if b >= b'0' && b <= b'9' {
            n = n * 10 + (b - b'0') as usize;
        } else {
            break;
        }
    }
    n
}


fn status_text(status: i32) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}
