// Waitless Example: HTTP Web Server
//
// Multi-page demo site running on the bare-metal unikernel.
// Each section lives at its own URL (`/`, `/architecture`,
// `/network`, `/tls`, `/quic`, `/diagnostics`).
//
// `#[waitless::init]` is the entry point. The macro spawns the body as
// a task; once it returns, listeners (registered via the `listen`
// helpers) keep running for the lifetime of the process. Shutdown
// (SIGINT / serial Ctrl-C) tears every retained listener down and
// drops the network stack symmetrically.
//
// The file is split three ways:
//   * `main.rs`      — boot/init, Alt-Svc, the request handlers,
//                      the `handle_request` router, compute helper.
//   * `pages.rs`     — the HTML site: the shared `shell_body` /
//                      `html_response` shell and the six `page_*`
//                      views. The shell emits the nav bar and a
//                      UTF-8 charset declaration so em-dashes and
//                      other glyphs render without a latin-1
//                      fallback.
//   * `endpoints.rs` — machine-facing data + diagnostic endpoints.

#![no_std]

extern crate alloc;

use http::{IOBufChain, Request, Response};
use waitless::net::Net;
use waitless::runtime::{TcpStream, UdpClient};

// HTML site (the `page_*` views + shared shell) and the machine-
// facing data/diagnostic endpoints each live in their own module;
// `handle_request` below routes into both.
mod endpoints;
mod pages;

use endpoints::*;
use pages::*;

// ---- Configuration ----------------------------------------------------------

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;
const GATEWAY_PORT: u16 = 9000;
const GATEWAY_BACKEND_PORT: u16 = 7777;
const GATEWAY_MSG_SIZE: usize = 32;

// TLS certificate material, baked in at build time. The default
// build uses the checked-in self-signed dev cert (ECDSA P-256 +
// SHA-256, `apps/webserver/dev_certs/`, regenerated via `regen.sh`);
// a `--define tls_cert=prod` build substitutes the real Let's Encrypt
// cert from `prod_certs/`. The `app` rule's `rustc_env` sets the
// `WAITLESS_TLS_*` paths — see `apps/webserver/BUILD.bazel`.
const TLS_LEAF_DER: &[u8] = include_bytes!(env!("WAITLESS_TLS_LEAF"));
const TLS_INTERMEDIATE_DER: &[u8] = include_bytes!(env!("WAITLESS_TLS_INTERMEDIATE"));
const TLS_KEY_PKCS8_DER: &[u8] = include_bytes!(env!("WAITLESS_TLS_KEY"));

/// DER certificate chain handed to the TLS / HTTP/3 listeners: the
/// leaf first, then the issuing intermediate when there is one. The
/// self-signed dev cert has no intermediate (an empty placeholder
/// file), so its chain is leaf-only; a real Let's Encrypt chain is
/// leaf + intermediate. Resolved at compile time — `is_empty` is
/// `const`.
const TLS_CERT_CHAIN: &[&[u8]] = if TLS_INTERMEDIATE_DER.is_empty() {
    &[TLS_LEAF_DER]
} else {
    &[TLS_LEAF_DER, TLS_INTERMEDIATE_DER]
};

// ---- Boot -------------------------------------------------------------------

#[waitless::init]
async fn init() {
    log_boot_info();

    // Boot-time AEAD KAT — runs NIST SP 800-38D Test Case 4
    // through the live AES-128-GCM implementation (AES-NI on
    // x86_64 with `+aes,+pclmul`; aarch64 NEON / FEAT_AES on
    // Apple Silicon). On a known-good build this prints
    // `aead-kat: ok`. On a CPU/compiler that produces wrong
    // ciphertext (the original chacha20-SIMD failure mode that
    // motivated this whole infrastructure) we get
    // `aead-kat: FAIL byte[i] expected=ee got=ff`, captured into
    // the diag buffer for `/diag-panic` to surface and on serial
    // for operators with serial access. Cheap (~few µs); safe to
    // run once per boot.
    {
        use waitless::diagnostics as diag;
        match tls::aead::rfc8439_kat() {
            Ok(()) => {
                waitless::println!("aead-kat: ok");
                diag::diag_append(b"aead-kat: ok\n");
            }
            Err(f) => {
                waitless::println!(
                    "aead-kat: FAIL at byte {}: expected=0x{:02x} got=0x{:02x}",
                    f.first_diverge_at,
                    f.expected,
                    f.actual,
                );
                diag::diag_append(b"aead-kat: FAIL at byte ");
                diag::diag_append_hex(f.first_diverge_at as u64);
                diag::diag_append(b"\n  expected: ");
                for &b in &f.expected_window {
                    diag::diag_append_hex_u8(b);
                    diag::diag_append(b" ");
                }
                diag::diag_append(b"\n  actual:   ");
                for &b in &f.actual_window {
                    diag::diag_append_hex_u8(b);
                    diag::diag_append(b" ");
                }
                diag::diag_append(b"\n");
            }
        }
        // Companion KAT for the hand-rolled `Aes128GcmFast` with
        // 8-block batched GHASH (deferred polynomial reduction).
        // 256-byte plaintext crosses the batched-chunk threshold
        // (>= 128 B) so any bit-order or reduction bug in
        // `ghash_batch::absorb_8` shows up at boot rather than in
        // a live TLS tag-verify failure later. Mirrors the
        // upstream/fast cross-check in
        // `aes_gcm_fast::tests::matches_aes_gcm_crate_roundtrip`.
        match tls::aead::aes_gcm_fast_kat() {
            Ok(()) => {
                waitless::println!("aead-fast-kat: ok");
                diag::diag_append(b"aead-fast-kat: ok\n");
            }
            Err(f) => {
                waitless::println!(
                    "aead-fast-kat: FAIL at byte {}: expected=0x{:02x} got=0x{:02x}",
                    f.first_diverge_at,
                    f.expected,
                    f.actual,
                );
                diag::diag_append(b"aead-fast-kat: FAIL at byte ");
                diag::diag_append_hex(f.first_diverge_at as u64);
                diag::diag_append(b"\n  expected: ");
                for &b in &f.expected_window {
                    diag::diag_append_hex_u8(b);
                    diag::diag_append(b" ");
                }
                diag::diag_append(b"\n  actual:   ");
                for &b in &f.actual_window {
                    diag::diag_append_hex_u8(b);
                    diag::diag_append(b" ");
                }
                diag::diag_append(b"\n");
            }
        }
    }

    let net = Net::up().await.expect("Net::up failed");
    let backend_ip = net.gateway().0;

    waitless::udp_listen(7, udp_echo).expect("udp echo bind");
    waitless::println!("listen udp://:7 (echo)");
    waitless::tcp_listen(9, tcp_echo).expect("tcp echo bind");
    waitless::println!("listen tcp://:9 (echo)");
    waitless::tcp_listen(GATEWAY_PORT, move |s| gateway(s, backend_ip)).expect("gateway bind");
    waitless::println!(
        "listen tcp://:{} (gateway → udp://{}.{}.{}.{}:{})",
        GATEWAY_PORT,
        backend_ip[0],
        backend_ip[1],
        backend_ip[2],
        backend_ip[3],
        GATEWAY_BACKEND_PORT
    );
    http::listen(HTTP_PORT, handle_request).expect("http bind");
    waitless::println!("listen tcp://:{} (http)", HTTP_PORT);

    let h3_up = match http3::listen(
        HTTPS_PORT,
        handle_request_h3,
        TLS_CERT_CHAIN,
        TLS_KEY_PKCS8_DER,
    ) {
        Ok(()) => {
            waitless::println!("listen udp://:{} (h3, TLS_AES_128_GCM_SHA256)", HTTPS_PORT);
            true
        }
        Err(_) => {
            waitless::println!("[WARN] h3 disabled (cert/key invalid or bind failed)");
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
    match tls::listen(
        HTTPS_PORT,
        handle_request_https,
        TLS_CERT_CHAIN,
        TLS_KEY_PKCS8_DER,
    ) {
        Ok(()) => waitless::println!(
            "listen tcp://:{} (https, TLS_AES_128_GCM_SHA256)",
            HTTPS_PORT
        ),
        Err(_) => waitless::println!("[WARN] https disabled (cert/key invalid)"),
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
static ALT_SVC_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

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
    let leaked: &'static [u8] = alloc::boxed::Box::leak(buf.into_boxed_slice());
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
async fn handle_request_https<S: http::HttpStream>(
    req: &Request,
    body: &mut http::BodyReader<'_, S>,
) -> Response {
    let resp = handle_request(req, body).await;
    match alt_svc_value() {
        Some(v) => resp.with_header(&b"Alt-Svc"[..], v),
        None => resp,
    }
}

/// H3-side request dispatch. Takes an owned `Request` (h3's
/// signature, since the QUIC stream is moved into the per-request
/// future) and the buffered body. The `user_handler_polled`
/// diag-counter bump matches the `user_handler_invoked` counter
/// the H3 server records BEFORE `handler(...).await`; a gap
/// between them means the future was constructed but never
/// polled, which would be a runtime/scheduler bug rather than
/// handler-internal work.
async fn handle_request_h3(req: Request, body: &mut http::BufferedBody<'_>) -> Response {
    http3::diag::COUNTERS.user_handler_polled.bump();
    handle_request(&req, body).await
}

// ---- Listener bodies --------------------------------------------------------

async fn udp_echo(sock: alloc::sync::Arc<waitless::runtime::UdpSocket>) {
    let mut buf = [0u8; 1500];
    loop {
        let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
        let _ = sock.send_to(src_ip, src_port, &buf[..n]);
    }
}

async fn tcp_echo(mut stream: TcpStream) {
    loop {
        // Zero-copy echo. `recv_chunk` surfaces the transport's own
        // buffer behind a guard — a NIC RX buffer on bare-metal, a
        // heap chunk on native. `into_owned()` consumes the guard
        // (releasing the `&mut stream` borrow) and yields an owned
        // IOBuf: zero-copy when it wraps the device RX buffer, which
        // then flows straight back out through `send` — RX buffer →
        // TX with no intermediate copy on bare-metal. Contrast the
        // old `recv` + `send_bytes`: device buf → `buf` → TX,
        // two copies.
        let guard = match waitless::runtime::timeout_us(30_000_000, stream.recv_chunk()).await {
            Some(Some(g)) => g,
            // inner `None`: peer close / EOF. outer `None`: idle
            // timeout. Either ends the connection.
            _ => return,
        };
        let mut chain = IOBufChain::new();
        chain.push_back(guard.into_owned());
        if stream.send(&mut chain).await.is_err() {
            return;
        }
    }
}

async fn gateway(mut stream: TcpStream, backend_ip: [u8; 4]) {
    let backend = waitless::runtime::IpAddr::V4(waitless::runtime::Ipv4Addr {
        addr: u32::from_ne_bytes(backend_ip),
    });
    let Ok(udp) = UdpClient::connect(backend, GATEWAY_BACKEND_PORT) else {
        return;
    };
    let mut buf = [0u8; GATEWAY_MSG_SIZE];
    loop {
        if stream.recv_exact(&mut buf).await.is_err() {
            return;
        }
        if udp.send(&buf).is_none() {
            return;
        }
        if udp.recv(&mut buf).await != GATEWAY_MSG_SIZE {
            return;
        }
        if stream.send_bytes(&buf).await.is_err() {
            return;
        }
    }
}

// ---- Request dispatch -------------------------------------------------------

async fn handle_request<S: http::HttpStream>(
    req: &Request,
    body: &mut http::BodyReader<'_, S>,
) -> Response {
    match req.path() {
        // ── HTML pages ───────────────────────────────────────────
        b"/" => page_home(),
        b"/architecture" => page_architecture(),
        b"/network" => page_network(),
        b"/tls" => page_tls(),
        b"/quic" => page_quic(),
        b"/diagnostics" => page_diagnostics(),

        // ── JSON / text data endpoints (kept for tests + tooling) ─
        b"/health" => Response::ok(b"application/json", HEALTH_JSON),

        // ── Static bulk-throughput endpoints ─────────────────────
        //
        // Fixed-size response bodies with zero dynamic rendering
        // cost — `STATIC_*_BYTES` are `&'static [u8]`, so
        // `Response::ok` builds a 1-part borrowed chain (no
        // alloc, no memcpy on the server side). Bench workloads
        // request these in a loop over keep-alive TLS to measure
        // the data-plane throughput ceiling (encrypt + TX
        // descriptor + wire) isolated from request parsing /
        // body rendering. `/diagnostics`-style dynamic pages
        // bundle real CPU work per request and don't surface the
        // wire ceiling.
        b"/static-16k" => Response::ok(b"application/octet-stream", STATIC_16K_BYTES.get()),
        b"/static-64k" => Response::ok(b"application/octet-stream", STATIC_64K_BYTES.get()),
        b"/static-256k" => Response::ok(b"application/octet-stream", STATIC_256K_BYTES.get()),
        b"/static-1m" => Response::ok(b"application/octet-stream", STATIC_1M_BYTES.get()),

        b"/stats" => stats_response(),
        b"/quic_stats" => quic_stats_response(),
        b"/obs" => obs_response(),
        b"/compute" => {
            core::hint::black_box(compute_work());
            Response::ok(b"application/json", b"{\"status\":\"computed\"}")
        }
        // Bulk-RX bench sink. Accepts POST of any length, drains
        // the body via the streaming `BodyReader` (the bytes
        // never sit in a single contiguous buffer — they flow
        // through `body.chunk()` and get dropped each iter), and
        // returns a tiny 200 OK. Paired with the `upload_*_*`
        // bench workloads — see scripts/bench/cli.py.
        b"/discard" => {
            // `chunk().await` yields the next run of body bytes as a
            // `BodyChunkGuard` — a zero-copy view over the parse
            // buffer's leading prebuf or, past it, the transport's
            // own RX buffer (item H of docs/rx-path-optimizations.md).
            // We don't look at the bytes; just walking the stream is
            // enough to advance the conn state past the body so the
            // next keep-alive request can parse correctly. `None`
            // ends the body.
            while let Some(chunk) = body.chunk().await {
                core::hint::black_box(chunk.data().len());
            }
            Response::ok(b"application/json", b"{\"status\":\"discarded\"}")
        }
        b"/tls_profile" => tls_profile_response(),
        b"/tls_profile_reset" => {
            tls::tls_profile_reset();
            Response::ok(b"text/plain; charset=utf-8", b"tls profile reset\n")
        }
        b"/diag-panic" => diag_panic_response(),
        b"/diag-panic-reset" => {
            waitless::diagnostics::diag_reset();
            Response::ok(b"text/plain; charset=utf-8", b"diag reset\n")
        }
        b"/diag-gve" => diag_gve_response(),

        _ => Response::not_found(),
    }
}

fn log_boot_info() {
    let bi = waitless::boot_info();
    waitless::println!(
        "app: ram={}MB cpus={} nics={}",
        bi.ram_bytes / (1024 * 1024),
        bi.num_cpus,
        bi.nics.len(),
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

