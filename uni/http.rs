// uni/http.rs — HTTP/1.1 server library (pure Rust, no_std)
//
// Non-blocking cooperative model: the kernel event loop polls the
// network stack, accepts connections, reads data, parses HTTP
// requests, dispatches to handlers, and sends responses.
//
// Multi-core: each core creates its own TCP listener and maintains
// its own active connection set. Core 0 runs the main event loop;
// APs run HTTP service via the percpu ap_poll hook. Routes are
// shared (read-only).
//
// HTTPS: TLS is injected from `//uni-tls` via the free function
// `uni_tls::listen_tls(&mut server, port, cfg)`, which hands us a
// `Box<dyn TlsAdapter>`. The service loop funnels incoming TCP
// bytes through that trait object, feeds decrypted plaintext into
// the same HTTP parser, encrypts responses back out. From the
// request-handler's perspective nothing changes — `Request` and
// `Response` are the same whether the transport is plain or TLS.
//
// The trait-object boundary means `uni::http::Server` itself has
// no dependency on TLS or crypto code — apps that don't pull
// `uni-tls` in don't link any of it.

use alloc::boxed::Box;

use crate::{TcpListener, TcpStream};

// ── TLS injection boundary ─────────────────────────────────────────────
//
// `uni-tls` implements these traits over its sans-io TLS 1.3 state
// machine; nothing else in the tree does. Making the boundary
// trait-object-based keeps the generated code for `Server` free of
// any TLS / crypto references when no `TlsAdapter` is installed.
//
// Shape mirrors the sans-io primitives exposed by
// `net_tls_server::TlsServer`:
//
//   push_rx         → feed ciphertext bytes off the wire
//   advance         → drive the handshake + state transitions
//   pop_tx          → drain ciphertext bytes to send back out
//   pop_plaintext   → drain decrypted request bytes for HTTP parse
//   send_app_data   → queue a plaintext response for encryption
//   close_notify    → queue a TLS shutdown alert before FIN

/// Adapter held by `Server` while TLS is enabled. Creates a per-
/// connection state machine each time the server accepts on a TLS
/// listener. `Send + Sync` because it's shared across all worker
/// cores; `'static` because it lives in a long-lived server.
pub trait TlsAdapter: Send + Sync + 'static {
    /// Build a fresh per-connection state machine. `seed` is 32
    /// bytes of platform entropy the caller has already pulled from
    /// the RNG.
    fn new_connection(&self, seed: [u8; 32]) -> Box<dyn TlsConnection>;
}

/// Per-connection TLS state. Accessed by one worker at a time (the
/// one that owns the `ActiveConn`), so `Send` is sufficient — no
/// `Sync` required.
pub trait TlsConnection: Send + 'static {
    fn push_rx(&mut self, bytes: &[u8]);
    /// Drive the handshake / state transitions. `Err(())` means a
    /// fatal error and the caller should drop the connection.
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
    buf: Box<[u8]>,
    buf_len: usize,
    /// Idle counter: incremented each service_core() call when no data
    /// arrives. Reset to 0 on activity. Used to close stale connections
    /// and reclaim slots (prevents pool exhaustion from abandoned clients).
    idle_ticks: u32,
    /// Per-connection TLS state (when the server is in HTTPS mode).
    /// `None` for plain HTTP connections. The trait object comes
    /// from `TlsAdapter::new_connection` — uni-tls implements it
    /// over the sans-io state machine in `//net:tls_server`, but
    /// `Server` itself is TLS-agnostic.
    tls: Option<Box<dyn TlsConnection>>,
}

/// Close idle connections after this many service ticks with no data.
/// At ~800K ticks/sec (single-core event loop), 4M ticks ≈ 5 seconds.
const IDLE_TIMEOUT_TICKS: u32 = 4_000_000;

// `uni::rng::fill_bytes` handles the platform cfg-switch — see
// that module for the backend split (kernel::rng on unikernel,
// getentropy(2) on native).

impl ActiveConn {
    fn new() -> Self {
        // Heap-allocated zero-filled receive buffer. `vec!` uses the
        // global allocator; `panic=abort` on OOM is acceptable here
        // because this runs once per pool slot during boot, well
        // before any connection traffic — if the heap can't fit the
        // pool, the kernel is DOA regardless.
        let buf: Box<[u8]> = alloc::vec![0u8; BUF_SIZE].into_boxed_slice();
        ActiveConn {
            conn: None,
            buf,
            buf_len: 0,
            idle_ticks: 0,
            tls: None,
        }
    }
}

/// Per-core HTTP state: up to one plain-HTTP listener, up to one
/// HTTPS listener, and the shared active-connection pool. Both
/// listeners feed into the same pool; a connection is marked TLS
/// (via `ActiveConn.tls`) based on which listener accepted it.
struct CoreHttp {
    /// Plain HTTP listener (e.g. port 80). `None` if the server
    /// isn't serving plain HTTP on this core.
    http_listener: Option<TcpListener>,
    /// HTTPS listener (e.g. port 443). `None` if the server isn't
    /// serving TLS on this core.
    tls_listener: Option<TcpListener>,
    active: [ActiveConn; MAX_ACTIVE],
}

impl CoreHttp {
    fn new() -> Self {
        CoreHttp {
            http_listener: None,
            tls_listener: None,
            active: core::array::from_fn(|_| ActiveConn::new()),
        }
    }
}

pub struct Server {
    routes: [Route; MAX_ROUTES],
    route_count: usize,
    default_handler: Option<Handler>,
    cores: [CoreHttp; MAX_CORES],
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
    /// Allocate a `Server`, including its per-connection receive buffers,
    /// on the heap. The returned `Box<Server>` is the only handle; callers
    /// typically `Box::leak` it to get a `&'static mut Server` for the
    /// duration of the program.
    pub fn new_boxed() -> Box<Self> {
        Box::new(Server {
            routes: [const { Route::new() }; MAX_ROUTES],
            route_count: 0,
            default_handler: None,
            cores: core::array::from_fn(|_| CoreHttp::new()),
            tls_adapter: None,
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
        let nw = crate::num_workers();

        // Create a listener per worker (SO_REUSEPORT on native,
        // per-core TCP pool on unikernel).
        let mut ok_any = false;
        for i in 0..nw {
            let handle = crate::tcp_listen_on(i, port);
            if handle.is_null() {
                crate::log(b"http: failed to create HTTP listener\n");
                if i == 0 { return; }
            } else {
                self.cores[i as usize].http_listener = Some(TcpListener(handle));
                ok_any = true;
            }
        }
        if !ok_any { return; }

        SERVER_PTR.store(self as *mut Server, core::sync::atomic::Ordering::Release);
        HTTP_LISTEN_PORT.store(port, core::sync::atomic::Ordering::Release);
        crate::set_service(http_service_cb);

        crate::log(b"http: listening (plain)\n");
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

        let nw = crate::num_workers();
        let mut ok_any = false;
        for i in 0..nw {
            let handle = crate::tcp_listen_on(i, port);
            if handle.is_null() {
                crate::log(b"http: failed to create HTTPS listener\n");
                if i == 0 { return; }
            } else {
                self.cores[i as usize].tls_listener = Some(TcpListener(handle));
                ok_any = true;
            }
        }
        if !ok_any { return; }

        SERVER_PTR.store(self as *mut Server, core::sync::atomic::Ordering::Release);
        TLS_LISTEN_PORT.store(port, core::sync::atomic::Ordering::Release);
        crate::set_service(http_service_cb);

        crate::log(b"http: listening (TLS)\n");
    }

    /// Service connections for a specific core. Returns true if any work was done.
    fn service_core(&mut self, core_id: u32) -> bool {
        let mut had_work = false;

        // Accept new connections from both listeners. Connections from
        // the plain HTTP listener are inserted with `tls=None`;
        // connections from the TLS listener are wrapped in a freshly
        // allocated `TlsServer`. Both share the same per-core
        // `active` pool so one HTTP client and one HTTPS client can
        // coexist without interfering.
        if let Some(listener) = self.cores[core_id as usize].http_listener {
            while let Some(stream) = listener.accept() {
                had_work = true;
                if let Some(ac) = alloc_active(&mut self.cores[core_id as usize].active) {
                    ac.conn = Some(stream);
                    ac.tls = None;
                } else {
                    crate::log(b"http: too many connections, dropping\n");
                    stream.close();
                    break;
                }
            }
        }
        if let Some(listener) = self.cores[core_id as usize].tls_listener {
            while let Some(stream) = listener.accept() {
                had_work = true;
                if let Some(ac) = alloc_active(&mut self.cores[core_id as usize].active) {
                    ac.conn = Some(stream);
                    if let Some(adapter) = self.tls_adapter.as_ref() {
                        // Seed the per-connection ephemeral X25519 keypair
                        // from platform entropy. `kernel::rng::fill_bytes`
                        // on bare-metal (ChaCha20 PRNG seeded at boot from
                        // the TSC/CNTVCT jitter + RDRAND); libc
                        // `arc4random_buf` on native (host OS entropy).
                        // Both are fine for TLS 1.3 ephemeral keys.
                        let mut seed = [0u8; 32];
                        crate::rng::fill_bytes(&mut seed);
                        ac.tls = Some(adapter.new_connection(seed));
                    } else {
                        // Shouldn't happen — `listen_tls()` always sets
                        // `self.tls_adapter` before creating the listener.
                        // Defensive: close the conn.
                        crate::log(b"http: tls listener but no adapter, dropping\n");
                        stream.close();
                        ac.conn = None;
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
                self.cores[core_id as usize].active[i].tls = None;
                had_work = true;
                continue;
            }

            // ── Read from TCP. TLS path funnels bytes through the ──
            // state machine; plain path goes direct to `buf`.
            if conn.has_data() {
                had_work = true;
                self.cores[core_id as usize].active[i].idle_ticks = 0;
                let is_tls =
                    self.cores[core_id as usize].active[i].tls.is_some();

                if is_tls {
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
                    self.cores[core_id as usize].active[i].tls = None;
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
                        self.cores[core_id as usize].active[i].tls = None;
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
                    self.cores[core_id as usize].active[i].tls = None;
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
    fn tls_ingest(&mut self, core_id: u32, conn_idx: usize, conn: TcpStream) {
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

        // Advance the state machine as far as possible. The trait
        // impl carries its own config reference, so no extra param.
        if tls.advance().is_err() {
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
            // If the response is closing the connection, queue a
            // TLS close_notify alert before draining tx so the peer
            // sees a clean TLS shutdown followed by a clean TCP FIN.
            // This silences OpenSSL's "unexpected eof while reading"
            // warning and lets well-behaved clients (curl, browsers)
            // distinguish between a deliberate close and a dropped
            // connection.
            if !keep_alive {
                let _ = tls.close_notify();
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
        // Fall through to plain-HTTP send when `tls` is None.
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
/// Add per-worker SO_REUSEPORT listeners on native. Called by native
/// worker threads after they spawn; re-creates whatever listeners
/// were configured via `listen()` / `listen_tls()` on core 0.
pub fn add_worker_listener(worker_id: u32) {
    let raw = SERVER_PTR.load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: SERVER_PTR is published once via Release in `Server::listen`;
    // the matching Acquire load above synchronises with that store. The
    // pointee outlives the program (it's the app's `static mut SERVER`).
    let server = unsafe { &mut *raw };

    let http_port = HTTP_LISTEN_PORT.load(core::sync::atomic::Ordering::Acquire);
    if http_port != 0 {
        let handle = crate::tcp_listen_on(worker_id, http_port);
        if !handle.is_null() {
            server.cores[worker_id as usize].http_listener = Some(TcpListener(handle));
        }
    }
    let tls_port = TLS_LISTEN_PORT.load(core::sync::atomic::Ordering::Acquire);
    if tls_port != 0 {
        let handle = crate::tcp_listen_on(worker_id, tls_port);
        if !handle.is_null() {
            server.cores[worker_id as usize].tls_listener = Some(TcpListener(handle));
        }
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
