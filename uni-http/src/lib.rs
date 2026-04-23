// HTTP/1.1 server. Cooperative non-blocking: the kernel event loop
// accepts, reads, parses, dispatches, and writes back.
//
// Per-core listener + connection set; routes are shared read-only.
// HTTPS injection happens via the `TlsAdapter` trait object below so
// this crate has no compile-time dep on TLS or crypto code.

#![no_std]

extern crate alloc;
extern crate uni;

use alloc::boxed::Box;


// TLS injection boundary. `uni-tls` implements these traits over a
// sans-io TLS 1.3 state machine.

pub trait TlsAdapter: Send + Sync + 'static {
    /// `seed` is 32 bytes of platform entropy the caller has already
    /// pulled from the RNG.
    fn new_connection(&self, seed: [u8; 32]) -> Box<dyn TlsConnection>;
}

pub trait TlsConnection: Send + 'static {
    fn push_rx(&mut self, bytes: &[u8]);
    /// `Err(())` is fatal — caller drops the connection.
    fn advance(&mut self) -> Result<(), ()>;
    fn pop_tx(&mut self, out: &mut [u8]) -> usize;
    fn pop_plaintext(&mut self, out: &mut [u8]) -> usize;
    fn send_app_data(&mut self, data: &[u8]) -> Result<(), ()>;
    fn close_notify(&mut self) -> Result<(), ()>;
}

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

/// Body storage for a `Response`. Either a borrowed byte slice (the
/// common case: `&'static [u8]` for compile-time strings like
/// INDEX_HTML / HEALTH_JSON), or a heap-owned `Box<[u8]>` for
/// dynamically rendered bodies (e.g. `/stats` / `/heap` /
/// `/tls_profile`). The enum is `#[repr(C)]` so `body_bytes` compiles
/// to a single conditional branch per access, not a vtable jump.
pub enum ResponseBody {
    /// A borrowed byte slice with lifetime that outlives `Response`.
    /// Stored as a raw pointer pair so the struct keeps its current
    /// `Send + Sync` properties without needing a lifetime parameter.
    /// Callers must ensure the bytes outlive the handler return /
    /// `send_response` call, which is always true for the `&'static`
    /// case that `Response::ok` covers.
    Static { ptr: *const u8, len: usize },
    /// A heap-owned byte slice. Dropped when `Response` drops, which
    /// happens after `send_response` has copied the bytes into the
    /// outbound TCP/TLS buffer.
    Owned(alloc::boxed::Box<[u8]>),
}

pub struct Response {
    pub status: i32,
    content_type: *const u8,
    content_type_len: usize,
    body: ResponseBody,
}

// Response is Send/Sync: the Static variant stores borrowed raw
// pointers whose targets live as long as the handler, and Owned
// holds a Box<[u8]> which is itself Send/Sync.
unsafe impl Send for Response {}
unsafe impl Sync for Response {}

impl Response {
    /// Build a 200 OK with a borrowed body. Zero-allocation common case.
    pub fn ok(content_type: &[u8], body: &[u8]) -> Self {
        Response {
            status: 200,
            content_type: content_type.as_ptr(),
            content_type_len: content_type.len(),
            body: ResponseBody::Static {
                ptr: body.as_ptr(),
                len: body.len(),
            },
        }
    }

    /// Build a 200 OK with a heap-owned body. Used by handlers that
    /// render JSON/text dynamically into a `Box<[u8]>` (e.g. via
    /// `vec![...].into_boxed_slice()`) rather than pointing into a
    /// fixed static scratch buffer. The allocation drops when the
    /// response drops — caller doesn't need to manage its lifetime.
    pub fn ok_owned(content_type: &[u8], body: alloc::boxed::Box<[u8]>) -> Self {
        Response {
            status: 200,
            content_type: content_type.as_ptr(),
            content_type_len: content_type.len(),
            body: ResponseBody::Owned(body),
        }
    }

    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: b"text/plain".as_ptr(),
            content_type_len: 10,
            body: ResponseBody::Static {
                ptr: b"Not Found".as_ptr(),
                len: 9,
            },
        }
    }

    fn body_bytes(&self) -> &[u8] {
        match &self.body {
            // SAFETY: the Static variant is constructed from a
            // caller-provided `&[u8]` whose lifetime covers the
            // handler return + send_response copy. See the comment
            // on ResponseBody::Static.
            ResponseBody::Static { ptr, len } => unsafe {
                core::slice::from_raw_parts(*ptr, *len)
            },
            ResponseBody::Owned(b) => b,
        }
    }
    fn content_type_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.content_type, self.content_type_len) }
    }
}

// ---- Handler type -----------------------------------------------------------

pub type Handler = fn(&Request) -> Response;

// ---- Server -----------------------------------------------------------------

const MAX_ROUTES: usize = 64;
const BUF_SIZE: usize = 8192;

/// Idle-connection timeout. After this long without inbound data,
/// the per-conn task tears down the connection and releases its
/// backend slot. Mirrors common HTTP/1.1 keep-alive budgets.
const IDLE_TIMEOUT_US: u64 = 30_000_000;

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

/// The async unikernel HTTP/1.1 server.
///
/// Model: one `uni::runtime::TcpListener::run` per registered port;
/// each accepted connection runs as its own async task on the
/// worker that accepted it. Per-conn state (receive buffer, parse
/// buffer, optional TLS state machine) lives on the task's stack,
/// not in a shared `MAX_ACTIVE` pool — the arena limit in the async
/// runtime caps concurrency.
///
/// `Server` itself holds only boot-time state: the route table,
/// default handler, and optional TLS adapter. After `listen()` /
/// `listen_tls()`, `SERVER_PTR` is published Release so each
/// spawned connection task can Acquire it and walk the routes.
pub struct Server {
    routes: [Route; MAX_ROUTES],
    route_count: usize,
    default_handler: Option<Handler>,
    /// TLS adapter, populated by `listen_tls()`. `None` for
    /// plain-HTTP-only servers. Each accepted HTTPS connection
    /// goes through `adapter.new_connection(seed)` to get its own
    /// `TlsConnection`. Owning the adapter here (rather than in a
    /// global) means an app can run multiple `Server` instances
    /// with different certs / configs.
    tls_adapter: Option<Box<dyn TlsAdapter>>,
}

// Global server pointer for AP poll callback / native worker threads.
// Written once during `Server::start()` on core 0; read from any core via
// the service callbacks. AtomicPtr lets multiple readers see a consistent
// pointer without forming `&mut` to a `static mut`.
static SERVER_PTR: core::sync::atomic::AtomicPtr<Server> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
// Plain HTTP listen port (needed by native worker threads to create
// SO_REUSEPORT listeners after main() returns). 0 = not listening on HTTP.
static HTTP_LISTEN_PORT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
// HTTPS listen port — same purpose as HTTP_LISTEN_PORT but for TLS.
static TLS_LISTEN_PORT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);

impl Server {
    /// Allocate a `Server` on the heap. Callers typically `Box::leak`
    /// the result to get a `&'static mut Server` that outlives the
    /// `listen()` / `listen_tls()` calls — per-conn tasks reach back
    /// into the route table via `SERVER_PTR` after the `Box` is
    /// permanently stored in the `uni::App` value.
    pub fn new_boxed() -> Box<Self> {
        Box::new(Server {
            routes: [const { Route::new() }; MAX_ROUTES],
            route_count: 0,
            default_handler: None,
            tls_adapter: None,
        })
    }

    /// Register an exact-path handler.
    pub fn route(&mut self, path: &[u8], handler: Handler) {
        if self.route_count >= MAX_ROUTES {
            uni::log(b"http: too many routes\n");
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

    /// Add a plain-HTTP listener on `port`. Creates a TCP listener on
    /// every worker (SO_REUSEPORT on native, per-core pool on
    /// unikernel). Non-blocking — returns immediately. Combine with
    /// `listen_tls()` to serve both HTTP and HTTPS on different
    /// ports with shared routes:
    ///
    /// ```ignore
    /// server.listen(80);                       // plain HTTP
    /// server.listen_tls(443, tls_config);      // HTTPS
    /// ```
    /// The workers start servicing requests once `uni::run(app)`
    /// signals readiness.
    pub fn listen(&mut self, port: u16) {
        SERVER_PTR.store(
            self as *mut Server,
            core::sync::atomic::Ordering::Release,
        );
        HTTP_LISTEN_PORT.store(port, core::sync::atomic::Ordering::Release);
        match uni::runtime::TcpListener::bind(port) {
            Ok(listener) => {
                listener.run(|stream| handle_plain_conn(stream));
                uni::log(b"http: listening (plain)\n");
            }
            Err(_) => uni::log(b"http: failed to bind HTTP listener\n"),
        }
    }

    /// Add an HTTPS (TLS 1.3) listener on `port`, with `adapter`
    /// supplying the per-connection state machine. Same semantics
    /// as `listen()` otherwise — routes registered via `route()` /
    /// `default_handler()` apply to both HTTP and HTTPS listeners
    /// identically.
    ///
    /// Callers in application code use `uni_tls::listen_tls(&mut
    /// server, port, cfg)` rather than calling this method directly
    /// — that free function constructs the `TlsAdapter` internally.
    /// The raw-adapter form stays `pub` so `uni-tls` (or a future
    /// alternate TLS implementation) can install itself without
    /// going through a private hook.
    pub fn listen_tls(&mut self, port: u16, adapter: Box<dyn TlsAdapter>) {
        self.tls_adapter = Some(adapter);
        SERVER_PTR.store(
            self as *mut Server,
            core::sync::atomic::Ordering::Release,
        );
        TLS_LISTEN_PORT.store(port, core::sync::atomic::Ordering::Release);
        match uni::runtime::TcpListener::bind(port) {
            Ok(listener) => {
                listener.run(|stream| handle_tls_conn(stream));
                uni::log(b"http: listening (TLS)\n");
            }
            Err(_) => uni::log(b"http: failed to bind HTTPS listener\n"),
        }
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

/// Access the registered `Server`. Returns `None` before `listen()` /
/// `listen_tls()` has been called. The pointer is published
/// Release-ordered and points at a leaked `Box<Server>`, so it
/// outlives every spawned connection task.
fn with_server<R, F: FnOnce(&Server) -> R>(f: F) -> Option<R> {
    let raw = SERVER_PTR.load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() {
        return None;
    }
    // SAFETY: SERVER_PTR is published once via Release in `listen*`;
    // the matching Acquire above synchronises. The pointee is
    // `Box::leak`-ed by the app (lives for process lifetime).
    Some(f(unsafe { &*raw }))
}

// ---- Per-connection async handlers ----------------------------------------

/// Plain-HTTP per-conn task. Consumes `stream` and drives one
/// keep-alive loop: recv → parse (possibly multiple pipelined
/// requests per recv) → dispatch → send.
async fn handle_plain_conn(stream: uni::TcpStream) {
    let mut buf = alloc::vec![0u8; BUF_SIZE].into_boxed_slice();
    let mut buf_len = 0usize;
    loop {
        if buf_len == BUF_SIZE {
            // Parse buffer full and no progress — client is
            // sending a request larger than we're prepared to
            // handle. Drop cleanly.
            stream.close();
            return;
        }
        let recv_fut = stream.recv(&mut buf[buf_len..]);
        let got = match uni::runtime::timeout_us(IDLE_TIMEOUT_US, recv_fut).await {
            Some(n) => n,
            None => {
                stream.close();
                return;
            }
        };
        if got == 0 {
            stream.close();
            return;
        }
        buf_len += got;

        // Drain every complete request sitting in the buffer.
        while buf_len > 0 {
            let mut req = Request::new();
            let consumed = parse_request(&buf[..buf_len], &mut req);
            if consumed == 0 {
                break; // need more bytes
            }
            let want_close = match req.get_header(b"Connection") {
                Some(v) => v.eq_ignore_ascii_case(b"close"),
                None => false,
            };
            let handler = with_server(|s| s.find_handler(req.path())).flatten();
            let resp = match handler {
                Some(h) => h(&req),
                None => Response::not_found(),
            };

            let mut w = BufWriter::new();
            write_response_into(&mut w, &resp, !want_close);
            if stream.send(w.as_bytes()).await.is_err() {
                stream.close();
                return;
            }
            drop(resp);

            if want_close {
                stream.close();
                return;
            }
            let remaining = buf_len - consumed;
            if remaining > 0 {
                buf.copy_within(consumed..buf_len, 0);
            }
            buf_len = remaining;
        }
    }
}

/// HTTPS per-conn task. Owns a heap-allocated `TlsConnection`
/// (built via the registered `TlsAdapter`) and pumps TCP↔TLS as
/// one loop: read raw bytes → push_rx → advance → pop_tx → send.
/// `pop_plaintext` into the HTTP parse buffer drives the same
/// request/response machinery as the plain path. The TLS handshake
/// and app-data phases share this loop — the state machine itself
/// tracks which records are handshake vs application.
async fn handle_tls_conn(stream: uni::TcpStream) {
    // Seed the per-conn ephemeral keypair. `uni::rng::fill_bytes`
    // abstracts the cfg split (ChaCha20 PRNG seeded at boot on
    // bare-metal, `arc4random_buf` / `getentropy` on native).
    let mut seed = [0u8; 32];
    uni::rng::fill_bytes(&mut seed);

    let tls_box = with_server(|s| {
        s.tls_adapter
            .as_ref()
            .map(|adapter| adapter.new_connection(seed))
    })
    .flatten();
    let Some(mut tls) = tls_box else {
        // `listen_tls()` was never called but a TLS port fired —
        // shouldn't happen; bail defensively.
        stream.close();
        return;
    };

    let mut recv_buf = alloc::vec![0u8; BUF_SIZE].into_boxed_slice();
    let mut plain_buf = alloc::vec![0u8; BUF_SIZE].into_boxed_slice();
    let mut plain_len = 0usize;
    let mut tx_scratch = alloc::vec![0u8; 2048].into_boxed_slice();

    loop {
        // --- Drain any pending TLS TX (handshake flight, encrypted
        // app-data from a previous iteration's response, alerts).
        loop {
            let n = tls.pop_tx(&mut tx_scratch);
            if n == 0 {
                break;
            }
            if stream.send(&tx_scratch[..n]).await.is_err() {
                stream.close();
                return;
            }
        }

        // --- Receive more ciphertext.
        let recv_fut = stream.recv(&mut recv_buf[..]);
        let got = match uni::runtime::timeout_us(IDLE_TIMEOUT_US, recv_fut).await {
            Some(n) => n,
            None => {
                stream.close();
                return;
            }
        };
        if got == 0 {
            stream.close();
            return;
        }
        tls.push_rx(&recv_buf[..got]);

        if tls.advance().is_err() {
            stream.close();
            return;
        }

        // --- Flush any output the advance produced before we
        // attempt plaintext / HTTP work.
        loop {
            let n = tls.pop_tx(&mut tx_scratch);
            if n == 0 {
                break;
            }
            if stream.send(&tx_scratch[..n]).await.is_err() {
                stream.close();
                return;
            }
        }

        // --- Pull any newly-decrypted plaintext into the parse
        // buffer.
        if plain_len < BUF_SIZE {
            let n = tls.pop_plaintext(&mut plain_buf[plain_len..]);
            plain_len += n;
        }

        // --- Parse + dispatch every complete request.
        while plain_len > 0 {
            let mut req = Request::new();
            let consumed = parse_request(&plain_buf[..plain_len], &mut req);
            if consumed == 0 {
                if plain_len >= BUF_SIZE {
                    stream.close();
                    return;
                }
                break;
            }
            let want_close = match req.get_header(b"Connection") {
                Some(v) => v.eq_ignore_ascii_case(b"close"),
                None => false,
            };
            let handler = with_server(|s| s.find_handler(req.path())).flatten();
            let resp = match handler {
                Some(h) => h(&req),
                None => Response::not_found(),
            };

            let mut w = BufWriter::new();
            write_response_into(&mut w, &resp, !want_close);
            if tls.send_app_data(w.as_bytes()).is_err() {
                stream.close();
                return;
            }
            if want_close {
                let _ = tls.close_notify();
            }
            drop(resp);

            // Drain the encrypted response out.
            loop {
                let n = tls.pop_tx(&mut tx_scratch);
                if n == 0 {
                    break;
                }
                if stream.send(&tx_scratch[..n]).await.is_err() {
                    stream.close();
                    return;
                }
            }

            if want_close {
                stream.close();
                return;
            }
            let remaining = plain_len - consumed;
            if remaining > 0 {
                plain_buf.copy_within(consumed..plain_len, 0);
            }
            plain_len = remaining;
        }
    }
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


/// Serialise an HTTP/1.1 response into a `BufWriter`. Split out so
/// the TLS path can reuse it and feed the bytes through `TlsServer`
/// instead of straight to `conn.send`.
fn write_response_into(w: &mut BufWriter, resp: &Response, keep_alive: bool) {
    use core::fmt::Write;

    let body = resp.body_bytes();
    let content_type = resp.content_type_bytes();
    let conn_header = if keep_alive { "keep-alive" } else { "close" };

    let _ = write!(w, "HTTP/1.1 {} {}\r\n", resp.status, status_text(resp.status));
    let _ = write!(w, "Content-Type: ");
    w.push(content_type);
    let _ = write!(
        w,
        "\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        body.len(),
        conn_header
    );
    w.push(body);
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
