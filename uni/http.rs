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
    content_type: *const u8,
    content_type_len: usize,
    body: *const u8,
    body_len: usize,
}

// Response stores pointers to caller-owned data. Safe because Response
// is always used within a single function scope (handler returns it,
// send_response consumes it immediately).
unsafe impl Send for Response {}
unsafe impl Sync for Response {}

impl Response {
    pub fn ok(content_type: &[u8], body: &[u8]) -> Self {
        Response {
            status: 200,
            content_type: content_type.as_ptr(),
            content_type_len: content_type.len(),
            body: body.as_ptr(),
            body_len: body.len(),
        }
    }

    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: b"text/plain".as_ptr(),
            content_type_len: 10,
            body: b"Not Found".as_ptr(),
            body_len: 9,
        }
    }

    fn body_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.body, self.body_len) }
    }
    fn content_type_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.content_type, self.content_type_len) }
    }
}

// ---- Handler type -----------------------------------------------------------

pub type Handler = fn(&Request) -> Response;

// ---- Server -----------------------------------------------------------------

const MAX_ROUTES: usize = 64;
const MAX_ACTIVE: usize = 8; // per core
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
    /// Heap-allocated receive buffer (BUF_SIZE bytes). Owning the bytes
    /// off-heap keeps `Server` small enough to live on the stack while
    /// being constructed in `Server::new()`.
    buf: crate::Buffer,
    buf_len: usize,
}

impl ActiveConn {
    fn new() -> Self {
        ActiveConn {
            conn: None,
            buf: crate::Buffer::new(BUF_SIZE),
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
    fn new() -> Self {
        CoreHttp {
            listener: None,
            active: core::array::from_fn(|_| ActiveConn::new()),
        }
    }
}

pub struct Server {
    routes: [Route; MAX_ROUTES],
    route_count: usize,
    default_handler: Option<Handler>,
    cores: [CoreHttp; MAX_CORES],
}

// Global server pointer for AP poll callback / native worker threads.
// Written once during `Server::start()` on core 0; read from any core via
// the service callbacks. AtomicPtr lets multiple readers see a consistent
// pointer without forming `&mut` to a `static mut`.
static SERVER_PTR: core::sync::atomic::AtomicPtr<Server> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
// Listen port (needed by native worker threads to create SO_REUSEPORT listeners).
static LISTEN_PORT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);

impl Server {
    /// Allocate a `Server`, including its per-connection receive buffers,
    /// on the heap. The returned `Box<Server>` is the only handle; callers
    /// typically `Box::leak` it to get a `&'static mut Server` for the
    /// duration of the program.
    pub fn new_boxed() -> crate::Box<Self> {
        crate::Box::new(Server {
            routes: [const { Route::new() }; MAX_ROUTES],
            route_count: 0,
            default_handler: None,
            cores: core::array::from_fn(|_| CoreHttp::new()),
        })
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

    /// Create TCP listeners and register the HTTP service callback.
    /// Non-blocking: returns immediately. The event loop (kernel or native)
    /// will call the service callback on each worker.
    pub fn listen(&mut self, port: u16) {
        let nw = crate::num_workers();

        // Create a listener per worker (SO_REUSEPORT on native,
        // per-core TCP pool on unikernel).
        for i in 0..nw {
            let handle = crate::tcp_listen_on(i, port);
            if handle.is_null() {
                crate::log(b"http: failed to create TCP listener\n");
                if i == 0 { return; }
            } else {
                self.cores[i as usize].listener = Some(TcpListener(handle));
            }
        }

        SERVER_PTR.store(self as *mut Server, core::sync::atomic::Ordering::Release);
        LISTEN_PORT.store(port, core::sync::atomic::Ordering::Release);
        crate::set_service(http_service_cb);

        crate::log(b"http: listening\n");
    }

    /// Start listening and enter the event loop. Blocks until shutdown.
    /// On unikernel: enters kernel event loop on core 0.
    /// On native: returns to main() which spawns worker threads.
    pub fn run(&mut self, port: u16) {
        self.listen(port);
        crate::set_ready();
        // On unikernel, this blocks forever. On native, it returns
        // and native.rs::main() handles thread management.
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
                conn.close(); // Send FIN if in CloseWait.
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

/// Event loop service callback: service HTTP connections on this core.
/// Network poll + inbox drain are handled by the event loop itself.
/// Add a listener for a specific worker. Called by native worker threads
/// to create their own SO_REUSEPORT listener.
pub fn add_worker_listener(worker_id: u32) {
    let port = LISTEN_PORT.load(core::sync::atomic::Ordering::Acquire);
    let raw = SERVER_PTR.load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: SERVER_PTR is published once via Release in `Server::start`;
    // the matching Acquire load above synchronises with that store. The
    // pointee outlives the program (it's the app's `static mut SERVER`).
    let server = unsafe { &mut *raw };
    let handle = crate::tcp_listen_on(worker_id, port);
    if !handle.is_null() {
        server.cores[worker_id as usize].listener = Some(TcpListener(handle));
    }
}

/// Event loop service callback — services HTTP connections on this worker.
/// Used by both unikernel (kernel event loop) and native (per-thread loop).
fn http_service_cb(core_id: u32) -> bool {
    let raw = SERVER_PTR.load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() { return false; }
    // SAFETY: see add_worker_listener.
    let server = unsafe { &mut *raw };
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
