// UniKernel Example: HTTP Web Server
//
// Multi-page demo site running on the bare-metal unikernel.
// Each section lives at its own URL (`/`, `/architecture`,
// `/network`, `/tls`, `/quic`, `/diagnostics`); they share a
// single shell function `page_shell` that emits the nav bar and
// a consistent UTF-8 charset declaration so em-dashes and other
// glyphs render correctly without browsers falling back to latin-1.
//
// `#[uni::init]` is the entry point. The macro spawns the body as
// a task; once it returns, listeners (registered via the `listen`
// helpers) keep running for the lifetime of the process. Shutdown
// (SIGINT / serial Ctrl-C) tears every retained listener down and
// drops the network stack symmetrically.

#![no_std]

extern crate alloc;

use core::fmt::Write as _;

use uni::net::Net;
use uni::runtime::{TcpStream, UdpClient};
use uni_http::{IOBufChain, Request, Response};

// ---- Configuration ----------------------------------------------------------

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;
const GATEWAY_PORT: u16 = 9000;
const GATEWAY_BACKEND_PORT: u16 = 7777;
const GATEWAY_MSG_SIZE: usize = 32;

// Self-signed dev cert + key (ECDSA P-256 + SHA-256). Regen via
// `apps/webserver/dev_certs/regen.sh`. NOT FOR PRODUCTION.
const DEV_CERT_DER: &[u8] = include_bytes!("../dev_certs/dev_cert.der");
const DEV_KEY_PKCS8_DER: &[u8] = include_bytes!("../dev_certs/dev_key.der");

// ---- Boot -------------------------------------------------------------------

#[uni::init]
async fn init() {
    log_boot_info();

    let net = Net::up().await.expect("Net::up failed");
    let backend_ip = net.gateway().0;

    uni::udp_listen(7, udp_echo).expect("udp echo bind");
    uni::println!("listen udp://:7 (echo)");
    uni::tcp_listen(9, tcp_echo).expect("tcp echo bind");
    uni::println!("listen tcp://:9 (echo)");
    uni::tcp_listen(GATEWAY_PORT, move |s| gateway(s, backend_ip))
        .expect("gateway bind");
    uni::println!("listen tcp://:{} (gateway → udp://{}.{}.{}.{}:{})",
        GATEWAY_PORT,
        backend_ip[0], backend_ip[1], backend_ip[2], backend_ip[3],
        GATEWAY_BACKEND_PORT);
    uni_http::listen(HTTP_PORT, handle_request).expect("http bind");
    uni::println!("listen tcp://:{} (http)", HTTP_PORT);

    let h3_handler = move |req: uni_http::Request| async move {
        // Bump the poll-entered counter the moment the future
        // body starts executing. A gap between `user_handler_invoked`
        // (set BEFORE handler(req).await in the H3 server) and
        // `user_handler_polled` would mean the future was built
        // but never polled — strong signal of a runtime/scheduler
        // bug rather than handler-internal work.
        uni_http3::diag::bump(&uni_http3::diag::COUNTERS.user_handler_polled);
        handle_request(&req).await
    };
    let h3_up = match uni_http3::listen(
        HTTPS_PORT, h3_handler, DEV_CERT_DER, DEV_KEY_PKCS8_DER,
    ) {
        Ok(()) => {
            uni::println!("listen udp://:{} (h3, TLS_CHACHA20_POLY1305_SHA256)", HTTPS_PORT);
            true
        }
        Err(_) => {
            uni::println!("[WARN] h3 disabled (cert/key invalid or bind failed)");
            false
        }
    };

    // Alt-Svc advertisement is app-side: when h3 is up we attach
    // `Alt-Svc: h3=":<port>"; ma=86400` to every HTTPS response
    // inside `handle_request_https`. The cached value is
    // installed once here at boot — see `install_alt_svc_for_h3`.
    // Apps that don't run h3 leave the cache pointer null and
    // pay nothing per HTTPS response.
    if h3_up {
        install_alt_svc_for_h3(HTTPS_PORT);
    }
    match uni_tls::listen(
        HTTPS_PORT, handle_request_https, DEV_CERT_DER, DEV_KEY_PKCS8_DER,
    ) {
        Ok(()) => uni::println!("listen tcp://:{} (https, TLS_CHACHA20_POLY1305_SHA256)", HTTPS_PORT),
        Err(_) => uni::println!("[WARN] https disabled (cert/key invalid)"),
    }
}

/// `Alt-Svc` value cached as `&'static [u8]` once at boot when
/// the H3 listener comes up. Pre-migration the per-response
/// `format_alt_svc_value(req.host_port())` was allocating a
/// fresh `Vec<u8>` AND reparsing the Host header AND a fresh
/// `Bytes::Owned` per HTTPS request — measurable on
/// `health_tls_max`. Lifting it to a one-shot install at boot
/// turns the per-request work into a single Acquire load + a
/// `Cow::Borrowed` construction.
///
/// Null when the H3 listener didn't come up (cert/key invalid,
/// UDP bind failed, etc.) — `handle_request_https` checks for
/// null and skips the header. The pre-existing `H3_UP` atomic
/// flag is gone; this pointer-or-null serves both purposes.
///
/// The pointer-len pair is published with Release / read with
/// Acquire to pair with `install_alt_svc_for_h3`'s store.
static ALT_SVC_PTR: core::sync::atomic::AtomicPtr<u8> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static ALT_SVC_LEN: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

fn install_alt_svc_for_h3(port: u16) {
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(32);
    buf.extend_from_slice(b"h3=\":");
    let mut tmp = [0u8; 5];
    let mut n = port;
    let mut len = 0usize;
    if n == 0 {
        tmp[0] = b'0';
        len = 1;
    } else {
        while n > 0 {
            tmp[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        tmp[..len].reverse();
    }
    buf.extend_from_slice(&tmp[..len]);
    buf.extend_from_slice(b"\"; ma=86400");
    let leaked: &'static [u8] =
        alloc::boxed::Box::leak(buf.into_boxed_slice());
    ALT_SVC_LEN.store(leaked.len(), core::sync::atomic::Ordering::Relaxed);
    ALT_SVC_PTR.store(
        leaked.as_ptr() as *mut u8,
        core::sync::atomic::Ordering::Release,
    );
}

#[inline]
fn alt_svc_value() -> Option<&'static [u8]> {
    let ptr = ALT_SVC_PTR.load(core::sync::atomic::Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    let len = ALT_SVC_LEN.load(core::sync::atomic::Ordering::Relaxed);
    // SAFETY: `ptr` was published from a `Box::leak` of a
    // `Box<[u8]>`, which has 'static lifetime. The Acquire load
    // pairs with the Release store in `install_alt_svc_for_h3`.
    // Length matches the slice length at install time and isn't
    // mutated after.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// HTTPS-specific dispatch. Calls into the shared
/// `handle_request` (used by both HTTPS and H3 paths) and, when
/// the H3 listener is up, layers a cached `Alt-Svc` header onto
/// the response.
async fn handle_request_https(req: &Request) -> Response {
    let resp = handle_request(req).await;
    match alt_svc_value() {
        Some(v) => resp.with_header(&b"Alt-Svc"[..], v),
        None => resp,
    }
}

// ---- Listener bodies --------------------------------------------------------

async fn udp_echo(sock: alloc::sync::Arc<uni::runtime::UdpSocket>) {
    let mut buf = [0u8; 1500];
    loop {
        let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
        let _ = sock.send_to(src_ip, src_port, &buf[..n]);
    }
}

async fn tcp_echo(stream: TcpStream) {
    let mut buf = [0u8; 1024];
    loop {
        let Some(n) = uni::runtime::timeout_us(30_000_000, stream.recv(&mut buf)).await
        else { return; };
        if n == 0 { return; }
        if stream.send_bytes(&buf[..n]).await.is_err() { return; }
    }
}

async fn gateway(stream: TcpStream, backend_ip: [u8; 4]) {
    let backend = uni::runtime::IpAddr::V4(uni::runtime::Ipv4Addr {
        addr: u32::from_ne_bytes(backend_ip),
    });
    let Ok(udp) = UdpClient::connect(backend, GATEWAY_BACKEND_PORT) else { return; };
    let mut buf = [0u8; GATEWAY_MSG_SIZE];
    loop {
        if stream.recv_exact(&mut buf).await.is_err() { return; }
        if udp.send(&buf).is_err() { return; }
        if udp.recv(&mut buf).await != GATEWAY_MSG_SIZE { return; }
        if stream.send_bytes(&buf).await.is_err() { return; }
    }
}

// ---- Request dispatch -------------------------------------------------------

async fn handle_request(req: &Request) -> Response {
    match req.path() {
        // ── HTML pages ───────────────────────────────────────────
        b"/"             => page_home(),
        b"/architecture" => page_architecture(),
        b"/network"      => page_network(),
        b"/tls"          => page_tls(),
        b"/quic"         => page_quic(),
        b"/diagnostics"  => page_diagnostics(),

        // ── JSON / text data endpoints (kept for tests + tooling) ─
        b"/health"       => Response::ok(b"application/json", HEALTH_JSON),
        b"/stats"        => stats_response(),
        b"/heap"         => heap_response(),
        b"/quic_stats"   => quic_stats_response(),
        b"/compute" => {
            core::hint::black_box(compute_work());
            Response::ok(b"application/json", b"{\"status\":\"computed\"}")
        }
        b"/tls_profile"       => tls_profile_response(),
        b"/tls_profile_reset" => {
            uni_tls::tls_profile_reset();
            Response::ok(b"text/plain; charset=utf-8", b"tls profile reset\n")
        }

        _ => Response::not_found(),
    }
}

fn log_boot_info() {
    let bi = uni::boot_info();
    uni::println!(
        "app: ram={}MB cpus={} nics={}",
        bi.ram_bytes / (1024 * 1024), bi.num_cpus, bi.nics.len(),
    );
}

fn compute_work() -> u32 {
    let mut h: u32 = 2166136261;
    for i in 0..100_000u32 {
        h ^= i;
        h = h.wrapping_mul(16777619);
    }
    h
}

// ---- Page shell -------------------------------------------------------------

const NAV: &[(&str, &str)] = &[
    ("/", "Home"),
    ("/architecture", "Architecture"),
    ("/network", "Network"),
    ("/tls", "TLS"),
    ("/quic", "QUIC"),
    ("/diagnostics", "Diagnostics"),
];

const STYLES: &str = "<style>\
:root{--bg:#0a0a12;--bg2:#161629;--bg3:#1f1f3a;--fg:#e6e6f0;--accent:#4fc3f7;\
--muted:#8a8ab0;--ok:#7ee787;--warn:#f0b85a;--border:#2a2a44;}\
*{box-sizing:border-box;}\
html{scroll-behavior:smooth;}\
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;\
margin:0;background:var(--bg);color:var(--fg);line-height:1.6;\
-webkit-font-smoothing:antialiased;}\
nav{background:var(--bg2);padding:14px 20px;display:flex;gap:6px;\
flex-wrap:wrap;border-bottom:1px solid var(--border);position:sticky;top:0;\
z-index:10;backdrop-filter:blur(8px);}\
nav .brand{color:var(--accent);font-weight:600;margin-right:auto;\
text-decoration:none;letter-spacing:0.02em;font-size:15px;padding:6px 0;}\
nav a{color:var(--muted);text-decoration:none;padding:6px 12px;\
border-radius:5px;font-size:14px;transition:color 0.15s,background 0.15s;}\
nav a:hover{color:var(--fg);background:rgba(255,255,255,0.04);}\
nav a.active{color:var(--accent);background:rgba(79,195,247,0.12);}\
main{max-width:820px;margin:0 auto;padding:36px 22px 60px;}\
h1{color:var(--accent);margin:0 0 0.4em;font-size:2.1em;letter-spacing:-0.01em;}\
h2{color:var(--accent);border-bottom:1px solid var(--border);\
padding-bottom:6px;margin-top:2em;font-size:1.4em;}\
h3{color:#bfbfd8;font-size:1.05em;margin-top:1.6em;}\
p{margin:0.7em 0;}\
a{color:var(--accent);}\
code{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;\
background:var(--bg2);padding:2px 6px;border-radius:3px;font-size:0.9em;}\
pre{background:var(--bg2);padding:16px;border-radius:8px;overflow-x:auto;\
border:1px solid var(--border);font-size:0.88em;}\
pre code{background:none;padding:0;font-size:1em;}\
.lead{color:#c4c4dd;font-size:1.08em;margin-bottom:1.2em;}\
.stat{display:inline-block;margin:4px 8px 4px 0;padding:5px 11px;\
background:var(--bg2);border:1px solid var(--border);border-radius:5px;\
font-size:0.86em;color:#bfbfd8;}\
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));\
gap:16px;margin-top:24px;}\
.card{background:var(--bg2);padding:18px 20px;border-radius:8px;\
border:1px solid var(--border);transition:border-color 0.15s,transform 0.1s;\
text-decoration:none;display:block;color:var(--fg);}\
.card:hover{border-color:var(--accent);transform:translateY(-1px);}\
.card h3{margin:0 0 6px;color:var(--accent);font-size:1em;}\
.card p{color:var(--muted);margin:0;font-size:0.9em;line-height:1.5;}\
table{border-collapse:collapse;width:100%;margin:14px 0;font-size:0.92em;}\
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);}\
th{color:var(--muted);font-weight:500;font-size:0.78em;\
text-transform:uppercase;letter-spacing:0.06em;}\
td.num{font-family:ui-monospace,monospace;text-align:right;color:#d8d8e8;}\
.proto-list{list-style:none;padding:0;}\
.proto-list li{padding:10px 14px;background:var(--bg2);border:1px solid var(--border);\
border-radius:6px;margin:8px 0;}\
.proto-list strong{color:var(--accent);}\
.kbd{font-family:ui-monospace,monospace;background:var(--bg3);padding:1px 6px;\
border-radius:3px;border:1px solid var(--border);font-size:0.85em;}\
.note{padding:12px 16px;background:var(--bg2);border-left:3px solid var(--accent);\
border-radius:0 6px 6px 0;margin:14px 0;font-size:0.95em;color:#c4c4dd;}\
footer{color:var(--muted);font-size:0.82em;padding:24px 20px;\
border-top:1px solid var(--border);max-width:820px;margin:40px auto 0;\
display:flex;flex-wrap:wrap;gap:14px;justify-content:space-between;}\
.proto-badge{display:inline-block;padding:1px 8px;border-radius:3px;\
font-size:0.72em;font-weight:600;background:var(--accent);color:var(--bg);\
margin-left:8px;letter-spacing:0.02em;}\
hr{border:0;border-top:1px solid var(--border);margin:28px 0;}\
</style>";

/// Static prefix that ends right before `<title>`. Same on
/// every page (charset, viewport meta).
const SHELL_HEAD_BEFORE_TITLE: &[u8] =
    b"<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>";
/// Between the page title and STYLES.
const SHELL_HEAD_AFTER_TITLE: &[u8] = b" \xE2\x80\x94 UniKernel</title>";
/// Between STYLES and the nav block (which the active-link
/// loop builds dynamically because of the `class="active"`
/// flip).
const SHELL_AFTER_STYLES: &[u8] = b"</head><body><nav><a class=\"brand\" href=\"/\">\xE2\xAC\xA2 UniKernel</a>";
/// Static between nav and main.
const SHELL_NAV_MAIN: &[u8] = b"</nav><main>";
/// Static suffix from the close of `<main>` through `</html>`.
const SHELL_FOOTER: &[u8] =
    b"</main><footer><span>UniKernel v0.1.0 \xC2\xB7 bare-metal Rust \xC2\xB7 no OS, no syscalls</span><span><a href=\"/diagnostics\">Live stats \xE2\x86\x92</a></span></footer></body></html>";

/// Build an `IOBufChain` for the page shell, taking the page
/// title and the inner-page body. The shell's static chrome is
/// queued by reference (zero alloc, zero copy) — only the bits
/// that vary per page (title, nav-link active-class flip) get
/// allocated.
///
/// Heap-owned chunks are rendered directly into IOBufs with
/// TLS record headroom (5 B) + tailroom (17 B = 1 type byte +
/// 16 B AEAD tag). `TlsStream::send_chain` then takes the
/// encrypt-in-place path on those parts: no plaintext memcpy
/// into `tls.tx_buf`, AEAD seals straight into the IOBuf the
/// app handed up. Static parts can't be sealed in place
/// (immutable storage); they fall back to the slice-based
/// path transparently.
fn shell_body(active: &str, title: &str, body: IOBufChain) -> IOBufChain {
    use core::fmt::Write as _;

    // Title and nav chunks share the per-conn body scratch with
    // the page body — three `body_iobuf` calls = three sub-
    // ranges of one buffer = zero heap allocations for any of
    // them. Transport-framing reserves (TLS record header, AEAD
    // tag) live inside the IOBuf out of the app's view.
    let title_cap = title.len().max(1);
    let mut title_buf = uni_http::body_iobuf(title_cap);
    let _ = title_buf.append_slice(title.as_bytes());

    // 512 B covers the current 6-link nav with active-class flip;
    // the writer truncates above that.
    const NAV_CAP: usize = 512;
    let mut nav_buf = uni_http::body_iobuf(NAV_CAP);
    {
        let mut w = nav_buf.writer();
        for (path, label) in NAV {
            let class = if *path == active { " class=\"active\"" } else { "" };
            let _ = write!(w, "<a href=\"{}\"{}>{}</a>", path, class, label);
        }
    }

    let mut chain = uni_http::IOBufChain::with_capacity(8 + body.part_count());
    chain.push_static(SHELL_HEAD_BEFORE_TITLE);
    chain.push_back(title_buf);
    chain.push_static(SHELL_HEAD_AFTER_TITLE);
    chain.push_static(STYLES.as_bytes());
    chain.push_static(SHELL_AFTER_STYLES);
    chain.push_back(nav_buf);
    chain.push_static(SHELL_NAV_MAIN);
    // Splice the page body's parts in order. Each is an IOBuf
    // (static-borrow or heap-owned).
    for part in body.into_parts() {
        chain.push_back(part);
    }
    chain.push_static(SHELL_FOOTER);
    chain
}

fn html_response(active: &str, title: &str, body: impl Into<uni_http::IOBufChain>) -> Response {
    Response::ok(b"text/html; charset=utf-8", shell_body(active, title, body.into()))
}

// ---- Page bodies ------------------------------------------------------------

fn page_home() -> Response {
    let body = "\
<h1>UniKernel</h1>\
<p class=\"lead\">A bare-metal Rust web server. The whole stack — \
from interrupt vectors to HTTP/3 — runs as one binary at ring 0, \
in a single address space, with no OS kernel underneath.</p>\
<div>\
<span class=\"stat\">Ring 0 execution</span>\
<span class=\"stat\">Single address space</span>\
<span class=\"stat\">Async-Rust runtime</span>\
<span class=\"stat\">~10 ms cold boot</span>\
<span class=\"stat\">No syscalls</span>\
</div>\
<h2>Take the tour</h2>\
<div class=\"cards\">\
<a class=\"card\" href=\"/architecture\"><h3>Architecture →</h3>\
<p>What a unikernel actually is, our boot sequence, and the async \
runtime that ties it all together.</p></a>\
<a class=\"card\" href=\"/network\"><h3>Network stack →</h3>\
<p>L2 to L7 written from scratch — virtio-net, ARP, IPv4/IPv6, TCP, \
UDP, DHCP, NDP/SLAAC.</p></a>\
<a class=\"card\" href=\"/tls\"><h3>TLS 1.3 →</h3>\
<p>Hand-rolled TLS 1.3, ChaCha20-Poly1305, ECDSA P-256, session \
resumption tickets.</p></a>\
<a class=\"card\" href=\"/quic\"><h3>QUIC + HTTP/3 →</h3>\
<p>RFC 9000 v1, RFC 9001 TLS-over-QUIC, RFC 9114 H3, including 0-RTT \
and key update.</p></a>\
<a class=\"card\" href=\"/diagnostics\"><h3>Live diagnostics →</h3>\
<p>Counters from the NIC, heap, and QUIC stack. Refresh to watch the \
numbers move.</p></a>\
</div>\
<h2>Why bother?</h2>\
<p>Every layer of a normal web server hides behind a syscall and a \
kernel context switch. A unikernel collapses the stack: an HTTP \
handler that wants to read the next byte off the wire goes through \
exactly the code that puts that byte there, with no privilege \
boundary in between. The result is a system you can read end to \
end — and one where a packet trace lines up with code paths you \
can step through.</p>\
<div class=\"note\">This server you're reading right now is the \
unikernel. Open DevTools → Network → enable the <span class=\"kbd\">Protocol</span> \
column. With <span class=\"kbd\">--origin-to-force-quic-on</span> Chrome will \
upgrade to <code>h3</code>; otherwise it rides over HTTP/1.1 + TLS \
1.3 on TCP.</div>";
    html_response("/", "Home", body)
}

fn page_architecture() -> Response {
    let body = "\
<h1>Architecture</h1>\
<p class=\"lead\">A unikernel is a single binary that contains <em>all</em> \
the code needed to run a service — boot, drivers, network stack, \
TLS, application — and runs directly on the hardware (or hypervisor) \
with no general-purpose OS underneath.</p>\
<h2>One address space, one privilege level</h2>\
<p>A traditional Linux process running an HTTP server lives in a \
sandbox: its memory is page-table-isolated from other processes and \
from the kernel; every read of a socket crosses a syscall boundary; \
every received packet involves a context switch from kernel to user. \
This unikernel collapses that — there's exactly one address space, \
exactly one privilege level (ring 0), and exactly one binary. A \
function call from <code>uni_http::handle_request</code> down to \
<code>virtio_net::send</code> is just a function call.</p>\
<h2>Boot sequence</h2>\
<p>On x86_64 we boot via Limine in higher-half (kernel mapped to \
<code>0xFFFFFFFF80100000+</code>). On aarch64 we boot via a small \
PIE-linked stub that processes <code>R_AARCH64_RELATIVE</code> \
relocations from <code>.rela.dyn</code> before jumping to Rust. \
Either way the path is:</p>\
<pre><code>firmware  →  boot stub (asm)\n          →  early init: paging, percpu, IDT/GDT or GICv3\n          →  heap init (talc allocator)\n          →  device discovery (FDT or ACPI)\n          →  driver bring-up (virtio-net or gve)\n          →  async runtime start\n          →  app `#[uni::init]` body</code></pre>\
<h2>Async runtime</h2>\
<p>Single-threaded per-core cooperative multitasking. Tasks are \
heap-allocated futures owned by per-core arenas; <code>spawn</code> \
adds them to the local ready queue. Wait primitives:</p>\
<ul class=\"proto-list\">\
<li><strong>AsyncEvent</strong> — manual-reset signal. Used everywhere \
a producer needs to wake an awaiting task: TCP recv-ready, QUIC \
inbox push, stream data arrived.</li>\
<li><strong>Sleep / sleep_us</strong> — timer-driven wake. Kernel \
maintains a sorted timer list; idle path uses WFI/WFE plus a \
hypervisor-yield MMIO write under HVF.</li>\
<li><strong>timeout_us</strong> — wraps any future with a deadline. \
The HTTP keep-alive idle and the TCP echo timeout both use it.</li>\
</ul>\
<h2>Memory layout</h2>\
<p>Identity-mapped low memory plus an HHDM (Higher-Half Direct Map) \
on x86_64. Heap grows from the largest free region the firmware \
reports. No mmap, no swap, no page cache — RAM is just one \
contiguous arena split between code, statics, stack-per-core, and \
heap.</p>\
<div class=\"note\">No paging beyond the initial setup means we never \
take a TLB miss on a page that wasn't already mapped at boot — so \
the <code>/health</code> path latency is almost entirely \
crypto + protocol work, with no surprise cache stalls from a \
paging-walk.</div>";
    html_response("/architecture", "Architecture", body)
}

fn page_network() -> Response {
    let body = "\
<h1>Network stack</h1>\
<p class=\"lead\">L2 through L7 written from scratch. The application \
writes <code>stream.send(buf)</code>; that call descends through TCP, \
IP, Ethernet, virtio-net (or gve), into a transmit ring the device \
DMAs from. No socket layer, no skbuff allocation, no kernel.</p>\
<h2>Layer by layer</h2>\
<ul class=\"proto-list\">\
<li><strong>L2 — virtio-net / gve</strong> · multi-queue receive, lock-free per-core RX rings. \
Google's gVNIC supported on GCE; virtio-net on HVF and QEMU.</li>\
<li><strong>L3 — IPv4 + IPv6</strong> · ARP cache for v4, NDP cache for v6. \
SLAAC for v6 link-local from the MAC via modified EUI-64; RA-driven global \
prefix when on a router-equipped LAN.</li>\
<li><strong>L4 — TCP + UDP</strong> · per-flow hash steers traffic to the owning \
core; rx-inbox SPSC for cross-core delivery on the rare misroute. Single \
<code>IpAddr</code> enum unifies v4/v6 dispatch end to end.</li>\
<li><strong>Boot — DHCP</strong> · v4 via the standard <code>DISCOVER → OFFER → REQUEST → ACK</code> \
flow, with timeout-and-fall-back to a static NAT default \
(<code>10.0.2.15/24</code>, gateway <code>10.0.2.2</code>) so dev environments \
without a DHCP server still come up.</li>\
<li><strong>ICMPv6 + NDP</strong> · echo reply, neighbor solicit/advertise. Active \
NS on cache miss for outbound v6 packets, mirroring v4's ARP-on-miss.</li>\
</ul>\
<h2>Live counters</h2>\
<p>Per-queue RX frame counts and used-ring cursors live at \
<a href=\"/stats\"><code>/stats</code></a>; raw heap utilisation at \
<a href=\"/heap\"><code>/heap</code></a>. The <a href=\"/diagnostics\">Diagnostics</a> \
page renders these in a more readable shape.</p>\
<h2>Async at the socket layer</h2>\
<p>Listeners are plain async fns:</p>\
<pre><code>uni::tcp_listen(80, |stream| async move {\n    let mut buf = [0u8; 4096];\n    loop {\n        let n = stream.recv(&mut buf).await?;\n        if n == 0 { return; }\n        // ... handle bytes ...\n    }\n});</code></pre>\
<p>The reactor wakes <code>recv</code> when the corresponding TCP control \
block has bytes; until then the task parks with no host CPU cost \
(under HVF, the vCPU thread literally sleeps via a yield-MMIO \
write).</p>";
    html_response("/network", "Network", body)
}

fn page_tls() -> Response {
    let body = "\
<h1>TLS 1.3</h1>\
<p class=\"lead\">A hand-rolled TLS 1.3 handshake — no OpenSSL, no \
rustls. Just the parts needed to terminate HTTPS for a server.</p>\
<h2>Suite</h2>\
<ul class=\"proto-list\">\
<li><strong>Cipher</strong> · <code>TLS_CHACHA20_POLY1305_SHA256</code> \
exclusively. AES paths exist for QUIC's Initial-level packet \
protection (RFC 9001 mandates AES-128-GCM there) but post-handshake \
we're ChaCha20 only.</li>\
<li><strong>(EC)DHE group</strong> · X25519. The server's ephemeral \
keypair is fresh per connection.</li>\
<li><strong>Certificate</strong> · ECDSA P-256 + SHA-256 \
(<code>ecdsa_secp256r1_sha256 = 0x0403</code>). Chrome / Safari / \
LibreSSL all reject Ed25519 server signatures, so P-256 is the \
boring-correct choice for browser interop.</li>\
</ul>\
<h2>Resumption</h2>\
<p>After ClientFinished the server emits a <code>NewSessionTicket</code>: \
the resumption master secret is sealed under a process-wide AEAD key \
(generated lazily on first use) and handed to the client. On a \
later connection the client presents the ticket via <code>pre_shared_key</code>; \
binder verification against <code>Truncate(ClientHello)</code> proves \
freshness, the schedule resumes from the recovered RMS, and \
Cert+CertVerify are skipped — the slowest step (ECDSA signing) \
disappears.</p>\
<h2>0-RTT</h2>\
<p>QUIC adds a third stage: <code>client_early_traffic_secret</code> from \
the ticket's PSK lets the client send application data in the \
<em>first flight</em>. Replay protection is the application's job \
(idempotent methods only); see the <a href=\"/quic\">QUIC page</a> for \
how the keys flow.</p>\
<h2>Profile</h2>\
<p>Per-stage cycle counts for the most recent handshake batch are \
exposed at <a href=\"/tls_profile\"><code>/tls_profile</code></a> as plain \
text. <code>/tls_profile_reset</code> clears the running average.</p>\
<div class=\"note\">The dev cert is a self-signed ECDSA P-256 with \
SAN <code>localhost / 127.0.0.1 / ::1 / unikernel.local</code>. \
For a Chrome-trusted local cert run \
<code>apps/webserver/dev_certs/regen-mkcert.sh</code> after \
<code>mkcert -install</code>.</div>";
    html_response("/tls", "TLS", body)
}

fn page_quic() -> Response {
    let body = "\
<h1>QUIC + HTTP/3</h1>\
<p class=\"lead\">RFC 9000 (transport), RFC 9001 (TLS-over-QUIC), \
RFC 9114 (HTTP/3 framing) — implemented from scratch. The stack \
runs on the same UDP port as HTTPS; browsers learn about it via the \
<code>Alt-Svc</code> header on the first HTTPS response.</p>\
<h2>What's wired up</h2>\
<ul class=\"proto-list\">\
<li><strong>QUIC v1</strong> <span class=\"proto-badge\">RFC 9000</span> · \
Initial / Handshake / 1-RTT packets; coalesced datagrams; PN \
reconstruction; flow control limits in transport_parameters.</li>\
<li><strong>0-RTT</strong> <span class=\"proto-badge\">RFC 9001 §4.6</span> · \
NewSessionTicket carries <code>max_early_data_size = 0xffffffff</code>; \
resumed handshakes derive <code>client_early_traffic_secret</code> from \
the PSK and accept early-data packets at the OneRtt namespace.</li>\
<li><strong>Key update</strong> <span class=\"proto-badge\">RFC 9001 §6</span> · \
On a peer-toggled <code>KEY_PHASE</code> bit, the server trial-decrypts \
with pre-derived next-phase keys, rotates, and stages another. \
Previous-phase keys retained for one rotation to absorb reordered \
stragglers.</li>\
<li><strong>Initial-DCID multiplexing</strong> · multi-packet \
ClientHellos (Chrome's PQ key_share routinely blows past 1200 bytes) \
all route to one connection regardless of which fragment arrived \
first.</li>\
<li><strong>HTTP/3</strong> <span class=\"proto-badge\">RFC 9114</span> · \
control stream + per-request bidi streams. QPACK <strong>static-only</strong> \
encoder + RFC 7541 Huffman decoder for headers.</li>\
</ul>\
<h2>The Alt-Svc dance</h2>\
<p>Browsers don't speak h3 cold — they need an HTTPS bootstrap. Our \
HTTPS responses carry:</p>\
<pre><code>Alt-Svc: h3=\":&lt;port&gt;\"; ma=86400</code></pre>\
<p>The port is read from the request's <code>Host</code> header so the \
advertisement matches whatever port the client connected to. After \
the first visit Chrome learns h3 is available and (on subsequent \
visits) races a QUIC handshake against TCP+TLS — whichever finishes \
first wins.</p>\
<div class=\"note\">On loopback TCP wins the race because zero-RTT \
network latency makes the extra crypto on the QUIC side dominate. \
Use <code>./scripts/open-browser-h3.sh</code> to launch Chrome with \
<code>--origin-to-force-quic-on=localhost:8443</code> for dev. Production \
RTTs swing the race the other way.</div>\
<h2>Live counters</h2>\
<p>Every hot-path drop and positive event in the QUIC stack is \
counted in <code>uni_quic::diag</code>. Render them as JSON at \
<a href=\"/quic_stats\"><code>/quic_stats</code></a> or via the \
<a href=\"/diagnostics\">Diagnostics</a> page. Set the boot arg \
<code>quic.log=events</code> to also emit human-readable lines per \
event on the serial console.</p>";
    html_response("/quic", "QUIC", body)
}

fn page_diagnostics() -> Response {
    // Build the dynamic body straight into an IOBuf with reserved
    // headroom + tailroom for the TLS record envelope. The previous
    // version allocated a `String::with_capacity(8192)`, grew it as
    // content exceeded that, then `Body::from` copied the bytes
    // into a fresh IOBuf — two allocs + one large memcpy. With
    // `IOBufWriter`, `write!` renders directly into the buffer's
    // payload region; `TlsStream::send_iobuf` then takes the
    // encrypt-in-place path on the chunk (saves the plaintext-into-
    // tx_buf memcpy too).
    use core::fmt::Write as _;

    // Payload capacity: 12 KiB covers the worst-case rendered
    // diagnostics page (~9 KiB observed); past that the writer
    // truncates. `body_iobuf` borrows from the per-conn scratch
    // when called inside a handler (zero alloc) and falls back
    // to a fresh allocation otherwise — apps don't pick.
    const PAYLOAD_CAP: usize = 12 * 1024;
    let mut body = uni_http::body_iobuf(PAYLOAD_CAP);
    {
        let mut w = body.writer();

        let _ = w.write_str("\
<h1>Diagnostics</h1>\
<p class=\"lead\">Live counters from the unikernel. This page \
auto-refreshes every 5 seconds; raw JSON endpoints below.</p>\
<meta http-equiv=\"refresh\" content=\"5\">");

        // ── Heap ──────────────────────────────────────────────────────
        let heap = uni::diagnostics::heap_stats();
        let _ = w.write_str("<h2>Heap</h2><table>");
        let _ = w.write_str("<tr><th>Field</th><th>Value</th></tr>");
        let _ = write!(w,
            "<tr><td>allocated</td><td class=\"num\">{} B ({} KiB)</td></tr>",
            heap.allocated_bytes, heap.allocated_bytes / 1024);
        let _ = write!(w,
            "<tr><td>available</td><td class=\"num\">{} B ({} KiB)</td></tr>",
            heap.available_bytes, heap.available_bytes / 1024);
        let _ = write!(w,
            "<tr><td>claimed (heap size)</td><td class=\"num\">{} B ({} KiB)</td></tr>",
            heap.claimed_bytes, heap.claimed_bytes / 1024);
        let _ = write!(w,
            "<tr><td>live allocations</td><td class=\"num\">{}</td></tr>",
            heap.allocation_count);
        let _ = write!(w,
            "<tr><td>fragments</td><td class=\"num\">{}</td></tr>",
            heap.fragment_count);
        let _ = write!(w,
            "<tr><td>total allocations (lifetime)</td><td class=\"num\">{}</td></tr>",
            heap.total_allocation_count);
        let _ = w.write_str("</table>");
        let _ = w.write_str("<p><a href=\"/heap\"><code>/heap</code></a> · raw JSON</p>");

        // ── NIC RX queues ─────────────────────────────────────────────
        let counts = uni::diagnostics::net_rx_counts();
        let cursors = uni::diagnostics::net_rx_used_cursors();
        let nqp = uni::diagnostics::net_num_queue_pairs() as usize;
        let nqp_clamped = nqp.min(counts.len()).min(cursors.len());
        let _ = w.write_str("<h2>NIC RX queues</h2>");
        let _ = write!(w, "<p>{} queue pair{} negotiated.</p>",
            nqp, if nqp == 1 { "" } else { "s" });
        let _ = w.write_str("<table><tr><th>Queue</th><th>Frames RX'd</th>\
<th>Used (device)</th><th>Used (driver)</th></tr>");
        for i in 0..nqp_clamped {
            let _ = write!(w,
                "<tr><td>{}</td><td class=\"num\">{}</td>\
<td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                i, counts[i], cursors[i].0, cursors[i].1);
        }
        let _ = w.write_str("</table>");
        let _ = w.write_str("<p><a href=\"/stats\"><code>/stats</code></a> · raw JSON</p>");

        // ── QUIC counters ─────────────────────────────────────────────
        let _ = w.write_str("<h2>QUIC events &amp; drops</h2>");
        let _ = w.write_str("<table><tr><th>Counter</th><th>Value</th></tr>");
        for (name, value) in uni_quic::diag::snapshot() {
            let _ = write!(w,
                "<tr><td><code>{}</code></td><td class=\"num\">{}</td></tr>",
                name, value);
        }
        let _ = w.write_str("</table>");

        // ── HTTP/3 counters ───────────────────────────────────────────
        let _ = w.write_str("<h2>HTTP/3 events &amp; drops</h2>");
        let _ = w.write_str("<table><tr><th>Counter</th><th>Value</th></tr>");
        for (name, value) in uni_http3::diag::snapshot() {
            let _ = write!(w,
                "<tr><td><code>{}</code></td><td class=\"num\">{}</td></tr>",
                name, value);
        }
        let _ = w.write_str("</table>");
        let _ = w.write_str("<p><a href=\"/quic_stats\"><code>/quic_stats</code></a> · raw JSON · ");
        let _ = w.write_str("<a href=\"/tls_profile\"><code>/tls_profile</code></a> · TLS handshake timing</p>");
    }
    html_response("/diagnostics", "Diagnostics", body)
}

// ---- JSON / text data endpoints --------------------------------------------

const HEALTH_JSON: &[u8] =
    b"{\"status\":\"ok\",\"runtime\":\"unikernel\",\"version\":\"0.1.0\"}";

/// Emit `"name":[v0,v1,...]` into `w` without a leading comma.
/// Caller manages comma separators between fields. `T: Display`
/// covers every numeric width the diagnostics endpoints use
/// (`u64`, `u16`, `u32`, ...) without per-type duplication.
fn emit_json_array<W, T>(w: &mut W, name: &str, slice: &[T])
where
    W: core::fmt::Write,
    T: core::fmt::Display,
{
    let _ = write!(w, "\"{}\":[", name);
    for (i, v) in slice.iter().enumerate() {
        if i > 0 {
            let _ = w.write_str(",");
        }
        let _ = write!(w, "{}", v);
    }
    let _ = w.write_str("]");
}

/// Pearson chi-squared statistic comparing `observed` to a uniform
/// expected distribution: `Σ (O_i − E)² / E` where
/// `E = total / observed.len()`. Returns the statistic ×100 so the
/// consumer can treat it as a fixed-point value (no float pull).
///
/// Interpretation, with `df = observed.len() - 1`:
///   * `chi² < 100·χ²_{0.95, df}`  → consistent with uniform.
///     For df=3 (4 qps): χ²_{0.95, 3} = 7.815, so chi² < 781.
///   * `chi² > 100·χ²_{0.999, df}` → highly skewed.
///     For df=3: χ²_{0.999, 3} = 16.27, so chi² > 1627.
///
/// Caveat: χ² scales linearly with total N, so at bench-scale
/// (10⁷+ packets) every detectable imbalance — even a 1.3× max/min
/// ratio — produces "highly skewed" by this threshold. Pair with
/// [`max_min_ratio_x100`] for a magnitude that doesn't grow with
/// the sample size.
///
/// Returns 0 when there's no traffic (or only one bucket) — readers
/// should treat 0 as "no data", not "perfectly balanced".
fn rss_chi_squared_x100(observed: &[u64]) -> u64 {
    let n = observed.len() as u64;
    if n < 2 {
        return 0;
    }
    let total: u64 = observed.iter().sum();
    if total == 0 {
        return 0;
    }
    let expected = total / n;
    if expected == 0 {
        // Every bucket is fractional; statistic isn't meaningful.
        return 0;
    }
    let mut acc: u64 = 0;
    for &o in observed {
        let diff = if o > expected { o - expected } else { expected - o };
        // (diff² / expected) — at bench scale (≤ 10⁷ packets/q),
        // diff² fits in u64 with margin (10¹⁴ vs u64 max 1.8×10¹⁹).
        let term = diff.saturating_mul(diff) / expected;
        acc = acc.saturating_add(term);
    }
    acc.saturating_mul(100)
}

/// Peak-to-trough ratio of `observed` × 100. Returns
/// `max(observed) * 100 / max(min(observed), 1)`. A perfectly
/// uniform distribution returns 100; 200 means the hottest bucket
/// has 2× the load of the coldest. Independent of total volume,
/// so this stays meaningful at any traffic scale (unlike raw
/// chi-squared, which grows linearly with N).
///
/// Returns 0 when `observed` is empty or `max == 0`.
fn max_min_ratio_x100(observed: &[u64]) -> u64 {
    let mut min = u64::MAX;
    let mut max = 0u64;
    for &v in observed {
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    if max == 0 || min == u64::MAX {
        return 0;
    }
    max.saturating_mul(100) / min.max(1)
}

/// Per-queue RX frame counts + used-ring cursors + TX-side
/// saturation/scan-depth/per-qp counters. Lets a monitoring agent
/// or `/diagnostics` page see whether:
///   * RSS / per-core dispatch is spreading load evenly
///     (rx_frames / tx_packets even across qps)
///   * The TX pool is undersized for the offered load
///     (tx_small_full_spins climbing)
///   * The linear-scan acquire path is wasting cycles
///     (tx_small_avg_scan_depth high relative to pool size)
///   * TSO super-segments are saturating their pool
///     (tx_big_full_returns climbing)
fn stats_response() -> Response {
    let counts = uni::diagnostics::net_rx_counts();
    let cursors = uni::diagnostics::net_rx_used_cursors();
    let nqp = uni::diagnostics::net_num_queue_pairs() as usize;
    let tx = uni::diagnostics::net_tx_diag();

    // Project the (device_idx, driver_cursor) tuple into separate
    // u16 slices so `emit_json_array` can render them — needed
    // because the helper emits `T: Display` and there's no
    // sensible Display impl for `(u16, u16)`.
    let n = nqp.min(cursors.len());
    let mut used_dev = [0u16; 8];
    let mut used_drv = [0u16; 8];
    for i in 0..n {
        used_dev[i] = cursors[i].0;
        used_drv[i] = cursors[i].1;
    }

    // RSS imbalance metrics. `chi_squared` is the Pearson statistic
    // for "is this consistent with uniform" (good for stat-sig
    // tests), but at bench-scale traffic volumes even a small
    // imbalance produces a huge chi² because the metric grows
    // linearly with N. `max_min_ratio` is the human-readable
    // companion: 100 = perfectly balanced, 200 = hottest qp gets
    // 2× the coldest qp's load, etc. Independent of N. RX side
    // reflects RSS hashing; TX reflects per-core dispatch.
    let rx_slice = &counts[..nqp.min(counts.len())];
    let rx_chi = rss_chi_squared_x100(rx_slice);
    let rx_ratio = max_min_ratio_x100(rx_slice);

    // 2 KiB body region — covers nqp ≤ 32 with TX/RX arrays + the
    // small set of saturation scalars and stays well under cap.
    let mut body = uni_http::body_iobuf(2048);
    {
        let mut w = body.writer();
        let _ = w.write_str("{");
        emit_json_array(&mut w, "rx_frames", &counts[..nqp.min(counts.len())]);
        let _ = w.write_str(",");
        emit_json_array(&mut w, "rx_used_dev", &used_dev[..n]);
        let _ = w.write_str(",");
        emit_json_array(&mut w, "rx_used_drv", &used_drv[..n]);
        let _ = write!(
            w,
            ",\"num_queue_pairs\":{},\
              \"rx_chi_squared_x100\":{},\
              \"rx_max_min_ratio_x100\":{}",
            nqp, rx_chi, rx_ratio,
        );

        if let Some(t) = tx {
            // Average scan depth: high values vs `small_pool_size`
            // motivate replacing the linear scan with a freelist.
            // Compute on the read side; emit as a fixed-point
            // ratio (×100) since we don't pull in float formatting.
            let avg_scan_x100 = if t.small_pool_acquires > 0 {
                (t.small_pool_scan_iters * 100) / t.small_pool_acquires
            } else {
                0
            };
            let tx_slice = &t.packets_per_qp[..nqp.min(t.packets_per_qp.len())];
            let inflight_slice = &t.inflight_per_qp[..nqp.min(t.inflight_per_qp.len())];
            let tx_chi = rss_chi_squared_x100(tx_slice);
            let tx_ratio = max_min_ratio_x100(tx_slice);
            let _ = w.write_str(",");
            emit_json_array(&mut w, "tx_packets", tx_slice);
            let _ = w.write_str(",");
            emit_json_array(&mut w, "tx_inflight", inflight_slice);
            let _ = write!(
                w,
                ",\"tx_chi_squared_x100\":{},\
                  \"tx_max_min_ratio_x100\":{},\
                  \"tx_small_pool_size\":{},\
                  \"tx_big_pool_size\":{},\
                  \"tx_small_acquires\":{},\
                  \"tx_small_scan_iters\":{},\
                  \"tx_small_avg_scan_x100\":{},\
                  \"tx_small_full_spins\":{},\
                  \"tx_big_acquires\":{},\
                  \"tx_big_full_returns\":{}",
                tx_chi,
                tx_ratio,
                t.small_pool_size,
                t.big_pool_size,
                t.small_pool_acquires,
                t.small_pool_scan_iters,
                avg_scan_x100,
                t.small_pool_full_spins,
                t.big_pool_acquires,
                t.big_pool_full_returns,
            );
        }
        let _ = w.write_str("}");
    }
    Response::ok(&b"application/json"[..], body)
}

fn heap_response() -> Response {
    // ~200 B JSON renders directly into the per-conn body
    // scratch via `body_iobuf`; transport-framing reserves are
    // handled inside the IOBuf out of view, so the encrypt-in-
    // place path in `TlsStream::send` applies for HTTPS.
    let s = uni::diagnostics::heap_stats();
    let mut body = uni_http::body_iobuf(256);
    let _ = write!(body.writer(),
        "{{\"allocated_bytes\":{},\"available_bytes\":{},\"claimed_bytes\":{},\
         \"allocation_count\":{},\"fragment_count\":{},\"total_allocation_count\":{}}}",
        s.allocated_bytes, s.available_bytes, s.claimed_bytes,
        s.allocation_count, s.fragment_count, s.total_allocation_count,
    );
    Response::ok(&b"application/json"[..], body)
}

/// Snapshot of the QUIC-stack counters (`uni_quic::diag::snapshot`).
/// Same numbers the Diagnostics page renders, exposed as JSON for
/// programmatic monitoring.
fn quic_stats_response() -> Response {
    // 1 KiB body region covers ~37 named u64 counters (the
    // current snapshot size); render in place to skip the
    // String → IOBuf copy.
    let mut body = uni_http::body_iobuf(1024);
    {
        let mut w = body.writer();
        let _ = w.write_str("{");
        let mut first = true;
        for (name, value) in uni_quic::diag::snapshot() {
            if !first { let _ = w.write_str(","); }
            first = false;
            let _ = write!(w, "\"{}\":{}", name, value);
        }
        let _ = w.write_str("}");
    }
    Response::ok(&b"application/json"[..], body)
}

const PROFILE_BUF_LEN: usize = 4096;

fn tls_profile_response() -> Response {
    let mut buf = alloc::vec![0u8; PROFILE_BUF_LEN];
    let n = uni_tls::tls_profile_report(buf.as_mut_slice());
    buf.truncate(n);
    Response::ok(b"text/plain; charset=utf-8", buf)
}
