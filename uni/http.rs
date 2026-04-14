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
// HTTPS: `Server::run_tls(port, config)` wraps each accepted connection
// in a `net_tls_server::TlsServer`. The service loop funnels incoming
// TCP bytes through the TLS state machine, feeds decrypted plaintext
// into the same HTTP parser, encrypts responses back out. From the
// request-handler's perspective nothing changes — the `Request` and
// `Response` types are identical.

use crate::{TcpListener, TcpStream};

// Re-export the TLS config type so apps can write `uni::http::TlsServerConfig`
// without caring which platform they're on. On the unikernel platform this
// is the real type from `//net:tls_server`; on native it's a lightweight
// stub (TLS isn't wired up for the POSIX backend).
#[cfg(platform_unikernel)]
pub use net::tls_server::TlsServerConfig;

/// Native-build stub for `TlsServerConfig`. Apps can construct it but
/// `run_tls()` on native ignores the config and falls back to plain HTTP.
#[cfg(platform_native)]
pub struct TlsServerConfig {
    pub cert_der: &'static [u8],
    pub signing_seed: [u8; 32],
}

#[cfg(platform_native)]
impl TlsServerConfig {
    pub fn from_dev_cert(cert_der: &'static [u8], _pkcs8_key: &[u8]) -> Option<Self> {
        Some(TlsServerConfig { cert_der, signing_seed: [0u8; 32] })
    }
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
const MAX_ACTIVE: usize = 64; // per core
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
    /// Idle counter: incremented each service_core() call when no data
    /// arrives. Reset to 0 on activity. Used to close stale connections
    /// and reclaim slots (prevents pool exhaustion from abandoned clients).
    idle_ticks: u32,
    /// Per-connection TLS state (when the server is in HTTPS mode).
    /// `None` for plain HTTP connections. Unikernel-only because the
    /// TLS 1.3 state machine lives in `//net:tls_server`, which isn't
    /// available on the native POSIX build.
    #[cfg(platform_unikernel)]
    tls: Option<crate::Box<net::tls_server::TlsServer>>,
}

/// Close idle connections after this many service ticks with no data.
/// At ~800K ticks/sec (single-core event loop), 4M ticks ≈ 5 seconds.
const IDLE_TIMEOUT_TICKS: u32 = 4_000_000;

impl ActiveConn {
    fn new() -> Self {
        ActiveConn {
            conn: None,
            buf: crate::Buffer::new(BUF_SIZE),
            buf_len: 0,
            idle_ticks: 0,
            #[cfg(platform_unikernel)]
            tls: None,
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

// TLS server configuration, published by `run_tls()`. None = plain HTTP.
// A raw pointer because `TlsServerConfig` isn't Send+Sync in the generic
// sense and we never form an `&mut`; readers dereference with Acquire
// and only read the immutable cert/key bytes.
#[cfg(platform_unikernel)]
static TLS_CONFIG_PTR: core::sync::atomic::AtomicPtr<net::tls_server::TlsServerConfig> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

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

    /// Start listening on `port` with TLS 1.3 wrapping for every
    /// accepted connection. The same HTTP routes apply — clients see
    /// an HTTPS endpoint, handlers see a `Request` / `Response` the
    /// same way they would for plain HTTP.
    ///
    /// `config` must outlive the server. Typically constructed from
    /// a `include_bytes!`-baked dev cert + PKCS#8 key (see
    /// `apps/webserver/dev_certs/`) and `Box::leak`-ed to get a
    /// `&'static TlsServerConfig`.
    ///
    /// Unikernel-only; on native, TLS is not currently supported and
    /// this function falls through to plain `run()`.
    #[cfg(platform_unikernel)]
    pub fn run_tls(&mut self, port: u16, config: &'static TlsServerConfig) {
        // Publish the config pointer so the per-connection accept
        // path can find it. `config` is `'static`, so the cast is
        // sound for the program's lifetime.
        TLS_CONFIG_PTR.store(
            config as *const _ as *mut _,
            core::sync::atomic::Ordering::Release,
        );
        self.listen(port);
        crate::set_ready();
    }

    #[cfg(platform_native)]
    pub fn run_tls(&mut self, port: u16, _config: &'static TlsServerConfig) {
        crate::log(b"http: run_tls() not supported on native; falling back to plain HTTP\n");
        self.run(port);
    }

    /// Service connections for a specific core. Returns true if any work was done.
    fn service_core(&mut self, core_id: u32) -> bool {
        let mut had_work = false;

        // Accept new connections. When the server is in TLS mode, each
        // accepted TcpStream also gets a freshly-allocated TlsServer
        // with a random X25519 ephemeral keypair. Construction costs
        // ~13 KB of stack while we initialise the state machine before
        // moving it into the heap via `crate::Box`.
        if let Some(listener) = self.cores[core_id as usize].listener {
            while let Some(stream) = listener.accept() {
                had_work = true;
                if let Some(ac) = alloc_active(&mut self.cores[core_id as usize].active) {
                    ac.conn = Some(stream);
                    #[cfg(platform_unikernel)]
                    {
                        let tls_cfg_ptr =
                            TLS_CONFIG_PTR.load(core::sync::atomic::Ordering::Acquire);
                        if !tls_cfg_ptr.is_null() {
                            let mut seed = [0u8; 32];
                            kernel::rng::fill_bytes(&mut seed);
                            ac.tls = Some(crate::Box::new(
                                net::tls_server::TlsServer::new(seed),
                            ));
                        }
                    }
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
                self.cores[core_id as usize].active[i].idle_ticks = 0;
                #[cfg(platform_unikernel)]
                { self.cores[core_id as usize].active[i].tls = None; }
                had_work = true;
                continue;
            }

            // ── Read from TCP. TLS path funnels bytes through the ──
            // state machine; plain path goes direct to `buf`.
            if conn.has_data() {
                had_work = true;
                self.cores[core_id as usize].active[i].idle_ticks = 0;
                #[cfg(platform_unikernel)]
                let is_tls =
                    self.cores[core_id as usize].active[i].tls.is_some();
                #[cfg(platform_native)]
                let is_tls = false;

                if is_tls {
                    #[cfg(platform_unikernel)]
                    self.tls_ingest(core_id, i, conn);
                } else {
                    let buf_len = self.cores[core_id as usize].active[i].buf_len;
                    let avail = BUF_SIZE - buf_len;
                    if avail > 0 {
                        let got = conn.recv(
                            &mut self.cores[core_id as usize].active[i].buf
                                [buf_len..buf_len + avail],
                        );
                        self.cores[core_id as usize].active[i].buf_len += got;
                    }
                }
            } else {
                // No data — bump idle counter and close if stale.
                self.cores[core_id as usize].active[i].idle_ticks =
                    self.cores[core_id as usize].active[i].idle_ticks.saturating_add(1);
                if self.cores[core_id as usize].active[i].idle_ticks >= IDLE_TIMEOUT_TICKS {
                    conn.close();
                    self.cores[core_id as usize].active[i].conn = None;
                    self.cores[core_id as usize].active[i].buf_len = 0;
                    self.cores[core_id as usize].active[i].idle_ticks = 0;
                    #[cfg(platform_unikernel)]
                    { self.cores[core_id as usize].active[i].tls = None; }
                    continue;
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

                    self.send_response_via(core_id, i, conn, &resp, !want_close);
                    self.cores[core_id as usize].active[i].idle_ticks = 0;
                    had_work = true;

                    if want_close {
                        conn.close();
                        self.cores[core_id as usize].active[i].conn = None;
                        self.cores[core_id as usize].active[i].buf_len = 0;
                        self.cores[core_id as usize].active[i].idle_ticks = 0;
                        #[cfg(platform_unikernel)]
                        { self.cores[core_id as usize].active[i].tls = None; }
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
                    #[cfg(platform_unikernel)]
                    { self.cores[core_id as usize].active[i].tls = None; }
                }
            }
        }

        had_work
    }

    /// Ingest TLS bytes from TCP for a single connection: read raw
    /// bytes from the socket, push them through the TLS state machine,
    /// drain any outbound TLS bytes the state machine produced back to
    /// the socket, and copy any plaintext the state machine decrypted
    /// into the per-connection `buf` for the HTTP parser to consume.
    ///
    /// Only called when the connection is known to be in TLS mode.
    #[cfg(platform_unikernel)]
    fn tls_ingest(&mut self, core_id: u32, conn_idx: usize, conn: TcpStream) {
        // Need an owned pointer to the TlsServerConfig. It's 'static.
        let tls_cfg_ptr = TLS_CONFIG_PTR.load(core::sync::atomic::Ordering::Acquire);
        if tls_cfg_ptr.is_null() {
            return;
        }
        // SAFETY: pointer is stored by run_tls() before listen() is
        // called, and points at a caller-owned 'static config.
        let tls_cfg: &'static net::tls_server::TlsServerConfig = unsafe { &*tls_cfg_ptr };

        let ac = &mut self.cores[core_id as usize].active[conn_idx];
        let Some(tls) = ac.tls.as_mut() else { return; };

        // Pull raw bytes off TCP into the TLS state machine. Loop to
        // drain the kernel TCP buffer in one go.
        let mut tmp = [0u8; 2048];
        loop {
            let got = conn.recv(&mut tmp);
            if got == 0 {
                break;
            }
            tls.push_rx(&tmp[..got]);
        }

        // Advance the state machine as far as possible.
        if tls.advance(tls_cfg).is_err() {
            // Fatal handshake failure — drop the connection.
            conn.close();
            ac.conn = None;
            ac.buf_len = 0;
            ac.idle_ticks = 0;
            ac.tls = None;
            return;
        }

        // Drain outgoing TLS bytes the state machine produced (server
        // flight during handshake, or encrypted responses during
        // application data phase).
        let mut out = [0u8; 2048];
        loop {
            let n = tls.pop_tx(&mut out);
            if n == 0 {
                break;
            }
            conn.send(&out[..n]);
        }

        // Copy any decrypted plaintext into the HTTP parse buffer.
        // `buf` is shared with the plain-HTTP path and holds HTTP
        // request bytes regardless of whether they arrived over TLS.
        let space = BUF_SIZE - ac.buf_len;
        if space > 0 {
            let start = ac.buf_len;
            let n = tls.pop_plaintext(&mut ac.buf[start..start + space]);
            ac.buf_len += n;
        }
    }

    /// Send `resp` on `conn`, routing through TLS if the connection
    /// has an active `TlsServer`. The plain-HTTP path preserves the
    /// original `send_response(conn, &resp, keep_alive)` shape.
    fn send_response_via(
        &mut self,
        core_id: u32,
        conn_idx: usize,
        conn: TcpStream,
        resp: &Response,
        keep_alive: bool,
    ) {
        #[cfg(platform_unikernel)]
        {
            let ac = &mut self.cores[core_id as usize].active[conn_idx];
            if let Some(tls) = ac.tls.as_mut() {
                // Build the HTTP response into a temporary stack
                // buffer, then feed it to TLS as application data.
                let mut w = BufWriter::new();
                write_response_into(&mut w, resp, keep_alive);
                if tls.send_app_data(w.as_bytes()).is_err() {
                    conn.close();
                    ac.conn = None;
                    ac.buf_len = 0;
                    ac.tls = None;
                    return;
                }
                let mut out = [0u8; 2048];
                loop {
                    let n = tls.pop_tx(&mut out);
                    if n == 0 {
                        break;
                    }
                    conn.send(&out[..n]);
                }
                return;
            }
        }
        // Fall through to plain-HTTP send on native or when tls is None.
        let _ = (core_id, conn_idx);
        send_response(conn, resp, keep_alive);
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
    let mut w = BufWriter::new();
    write_response_into(&mut w, resp, keep_alive);
    conn.send(w.as_bytes());
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
