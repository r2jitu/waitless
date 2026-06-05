// apps/webserver/src/pages.rs — the HTML site: the shared page
// shell and the six human-facing `page_*` views.
//
// Split out of `main.rs`; see the crate-root doc comment there for
// the overall app shape.

use http::{IOBufChain, Response};

pub(crate) const NAV: &[(&str, &str)] = &[
    ("/", "Home"),
    ("/architecture", "Architecture"),
    ("/network", "Network"),
    ("/tls", "TLS"),
    ("/quic", "QUIC"),
    ("/diagnostics", "Diagnostics"),
];

pub(crate) const STYLES: &str = "<style>\
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
pub(crate) const SHELL_HEAD_BEFORE_TITLE: &[u8] =
    b"<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>";
/// Between the page title and STYLES.
pub(crate) const SHELL_HEAD_AFTER_TITLE: &[u8] = b" \xE2\x80\x94 Waitless</title>";
/// Between STYLES and the nav block (which the active-link
/// loop builds dynamically because of the `class="active"`
/// flip).
pub(crate) const SHELL_AFTER_STYLES: &[u8] =
    b"</head><body><nav><a class=\"brand\" href=\"/\">\xE2\xAC\xA2 Waitless</a>";
/// Static between nav and main.
pub(crate) const SHELL_NAV_MAIN: &[u8] = b"</nav><main>";
/// Static suffix from the close of `<main>` through `</html>`.
pub(crate) const SHELL_FOOTER: &[u8] =
    b"</main><footer><span>Waitless v0.1.0 \xC2\xB7 bare-metal Rust \xC2\xB7 no OS, no syscalls</span><span><a href=\"/diagnostics\">Live stats \xE2\x86\x92</a></span></footer></body></html>";

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
pub(crate) fn shell_body(active: &str, title: &str, body: IOBufChain) -> IOBufChain {
    use core::fmt::Write as _;

    // Title and nav chunks share the per-conn body scratch with
    // the page body — three `body_iobuf` calls = three sub-
    // ranges of one buffer = zero heap allocations for any of
    // them. Transport-framing reserves (TLS record header, AEAD
    // tag) live inside the IOBuf out of the app's view.
    let title_cap = title.len().max(1);
    let mut title_buf = http::body_iobuf(title_cap);
    let _ = title_buf.append_slice(title.as_bytes());

    // 512 B covers the current 6-link nav with active-class flip;
    // the writer truncates above that.
    const NAV_CAP: usize = 512;
    let mut nav_buf = http::body_iobuf(NAV_CAP);
    {
        let mut w = nav_buf.writer();
        for (path, label) in NAV {
            let class = if *path == active {
                " class=\"active\""
            } else {
                ""
            };
            let _ = write!(w, "<a href=\"{}\"{}>{}</a>", path, class, label);
        }
    }

    let mut chain = http::IOBufChain::with_capacity(8 + body.part_count());
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

pub(crate) fn html_response(active: &str, title: &str, body: impl Into<http::IOBufChain>) -> Response<'static> {
    Response::ok(
        b"text/html; charset=utf-8",
        shell_body(active, title, body.into()),
    )
}

// ---- Page bodies ------------------------------------------------------------

pub(crate) fn page_home() -> Response<'static> {
    let body = "\
<h1>Waitless</h1>\
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
<p>Hand-rolled TLS 1.3, AES-128-GCM via AES-NI / FEAT_AES, ECDSA \
P-256, session resumption tickets.</p></a>\
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

pub(crate) fn page_architecture() -> Response<'static> {
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
function call from <code>http::handle_request</code> down to \
<code>virtio_net::send</code> is just a function call.</p>\
<h2>Boot sequence</h2>\
<p>On x86_64 we boot via Limine in higher-half (kernel mapped to \
<code>0xFFFFFFFF80100000+</code>). On aarch64 we boot via a small \
PIE-linked stub that processes <code>R_AARCH64_RELATIVE</code> \
relocations from <code>.rela.dyn</code> before jumping to Rust. \
Either way the path is:</p>\
<pre><code>firmware  →  boot stub (asm)\n          →  early init: paging, percpu, IDT/GDT or GICv3\n          →  heap init (talc allocator)\n          →  device discovery (FDT or ACPI)\n          →  driver bring-up (virtio-net or gve)\n          →  async runtime start\n          →  app `#[waitless::init]` body</code></pre>\
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

pub(crate) fn page_network() -> Response<'static> {
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
<p>Per-queue RX frame counts and used-ring cursors — and every \
subsystem's failure / performance counters — live in the aggregate \
<a href=\"/obs\"><code>/obs</code></a> surface. The \
<a href=\"/diagnostics\">Diagnostics</a> page renders these in a \
more readable shape.</p>\
<h2>Async at the socket layer</h2>\
<p>Listeners are plain async fns:</p>\
<pre><code>waitless::tcp_listen(80, |stream| async move {\n    let mut buf = [0u8; 4096];\n    loop {\n        let n = stream.recv(&mut buf).await?;\n        if n == 0 { return; }\n        // ... handle bytes ...\n    }\n});</code></pre>\
<p>The reactor wakes <code>recv</code> when the corresponding TCP control \
block has bytes; until then the task parks with no host CPU cost \
(under HVF, the vCPU thread literally sleeps via a yield-MMIO \
write).</p>";
    html_response("/network", "Network", body)
}

pub(crate) fn page_tls() -> Response<'static> {
    let body = "\
<h1>TLS 1.3</h1>\
<p class=\"lead\">A hand-rolled TLS 1.3 handshake — no OpenSSL, no \
rustls. Just the parts needed to terminate HTTPS for a server.</p>\
<h2>Suite</h2>\
<ul class=\"proto-list\">\
<li><strong>Cipher</strong> · <code>TLS_AES_128_GCM_SHA256</code> \
exclusively (RFC 8446 §9.1's mandatory-to-implement suite). The same \
AES-128-GCM AEAD also protects QUIC packets per RFC 9001, so the \
hardware path is shared between the TLS-over-TCP and HTTP/3 paths.</li>\
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
SAN <code>localhost / 127.0.0.1 / ::1 / waitless.local</code>. \
For a Chrome-trusted local cert run \
<code>apps/webserver/dev_certs/regen-mkcert.sh</code> after \
<code>mkcert -install</code>.</div>";
    html_response("/tls", "TLS", body)
}

pub(crate) fn page_quic() -> Response<'static> {
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
counted in <code>quic::diag</code>, and each anomaly category keeps \
a last-occurrence snapshot beside its counter — the received \
CONNECTION_CLOSE detail, the conn-task exit reason and its idle \
inputs. Render the lot as JSON at \
<a href=\"/quic_stats\"><code>/quic_stats</code></a>, in the \
aggregate <a href=\"/obs\"><code>/obs</code></a> surface, or via the \
<a href=\"/diagnostics\">Diagnostics</a> page. Set the boot arg \
<code>quic.log=events</code> to also emit human-readable lines per \
event on the serial console.</p>";
    html_response("/quic", "QUIC", body)
}

pub(crate) fn page_diagnostics() -> Response<'static> {
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
    let mut body = http::body_iobuf(PAYLOAD_CAP);
    {
        let mut w = body.writer();

        let _ = w.write_str(
            "\
<h1>Diagnostics</h1>\
<p class=\"lead\">Live counters from the unikernel. This page \
auto-refreshes every 5 seconds; raw JSON endpoints below.</p>\
<meta http-equiv=\"refresh\" content=\"5\">",
        );

        // ── Heap ──────────────────────────────────────────────────────
        let heap = waitless::diagnostics::heap_stats();
        let _ = w.write_str("<h2>Heap</h2><table>");
        let _ = w.write_str("<tr><th>Field</th><th>Value</th></tr>");
        let _ = write!(
            w,
            "<tr><td>allocated</td><td class=\"num\">{} B ({} KiB)</td></tr>",
            heap.allocated_bytes,
            heap.allocated_bytes / 1024
        );
        let _ = write!(
            w,
            "<tr><td>available</td><td class=\"num\">{} B ({} KiB)</td></tr>",
            heap.available_bytes,
            heap.available_bytes / 1024
        );
        let _ = write!(
            w,
            "<tr><td>claimed (heap size)</td><td class=\"num\">{} B ({} KiB)</td></tr>",
            heap.claimed_bytes,
            heap.claimed_bytes / 1024
        );
        let _ = write!(
            w,
            "<tr><td>live allocations</td><td class=\"num\">{}</td></tr>",
            heap.allocation_count
        );
        let _ = write!(
            w,
            "<tr><td>fragments</td><td class=\"num\">{}</td></tr>",
            heap.fragment_count
        );
        let _ = write!(
            w,
            "<tr><td>total allocations (lifetime)</td><td class=\"num\">{}</td></tr>",
            heap.total_allocation_count
        );
        let _ = w.write_str("</table>");
        let _ = w.write_str("<p><a href=\"/obs\"><code>/obs</code></a> · raw JSON</p>");

        // ── NIC RX queues ─────────────────────────────────────────────
        let counts = waitless::diagnostics::net_rx_counts();
        let cursors = waitless::diagnostics::net_rx_used_cursors();
        let nqp = waitless::diagnostics::net_num_queue_pairs() as usize;
        let nqp_clamped = nqp.min(counts.len()).min(cursors.len());
        let _ = w.write_str("<h2>NIC RX queues</h2>");
        let _ = write!(
            w,
            "<p>{} queue pair{} negotiated.</p>",
            nqp,
            if nqp == 1 { "" } else { "s" }
        );
        let _ = w.write_str(
            "<table><tr><th>Queue</th><th>Frames RX'd</th>\
<th>Used (device)</th><th>Used (driver)</th></tr>",
        );
        for i in 0..nqp_clamped {
            let _ = write!(
                w,
                "<tr><td>{}</td><td class=\"num\">{}</td>\
<td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                i, counts[i], cursors[i].0, cursors[i].1
            );
        }
        let _ = w.write_str("</table>");
        let _ = w.write_str("<p><a href=\"/obs\"><code>/obs</code></a> · raw JSON</p>");

        // ── QUIC counters ─────────────────────────────────────────────
        let _ = w.write_str("<h2>QUIC events &amp; drops</h2>");
        let _ = w.write_str("<table><tr><th>Counter</th><th>Value</th></tr>");
        for (name, value) in quic::diag::snapshot() {
            let _ = write!(
                w,
                "<tr><td><code>{}</code></td><td class=\"num\">{}</td></tr>",
                name, value
            );
        }
        let _ = w.write_str("</table>");

        // ── HTTP/3 counters ───────────────────────────────────────────
        let _ = w.write_str("<h2>HTTP/3 events &amp; drops</h2>");
        let _ = w.write_str("<table><tr><th>Counter</th><th>Value</th></tr>");
        for (name, value) in http3::diag::snapshot() {
            let _ = write!(
                w,
                "<tr><td><code>{}</code></td><td class=\"num\">{}</td></tr>",
                name, value
            );
        }
        let _ = w.write_str("</table>");
        let _ =
            w.write_str("<p><a href=\"/quic_stats\"><code>/quic_stats</code></a> · raw JSON · ");
        let _ = w.write_str(
            "<a href=\"/tls_profile\"><code>/tls_profile</code></a> · TLS handshake timing</p>",
        );
    }
    html_response("/diagnostics", "Diagnostics", body)
}

// ---- JSON / text data endpoints --------------------------------------------

