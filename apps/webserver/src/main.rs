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

    // Per-core QUIC egress scheduler (docs/tx-backpressure.md stage 3):
    // connections' outbound ships via a per-core DRR drain (the event loop's
    // egress-drain hook), build-at-drain with per-packet zero-copy — fairly
    // arbitrating one core's TX queue across many flows. GCE-validated
    // (+3.9% h3 /health rps, no slot-aliasing at 24 ms RTT), so it is simply
    // the configuration now, not a lever. Conns past the per-core flow-table
    // capacity degrade to the inline eager/heap path automatically.
    // Must run before any QUIC listener spawns (workers are already up).
    quic::egress::enable();
    kernel_bare::eventloop::set_egress_drain(quic::egress::drain_current_core);

    // One call brings up all of HTTPS: h1.1 + h2 over TLS/TCP and h3
    // over QUIC/UDP on the same port, with the `Alt-Svc` h3
    // advertisement wired automatically. The *same* `handle_request`
    // serves every transport — its `(&mut Request<'_>, &mut Response<'_>)`
    // signature is transport-erased, so no per-version wrapper is
    // needed (it's the same handler plain `http::listen` takes above).
    // h3 is best-effort inside `serve` — the TCP server still comes up
    // if the UDP bind fails.
    match https::serve(HTTPS_PORT, handle_request, TLS_CERT_CHAIN, TLS_KEY_PKCS8_DER) {
        Ok(served) => {
            waitless::println!(
                "listen :{} (https — h1.1+h2/TLS{}, TLS_AES_128_GCM_SHA256)",
                HTTPS_PORT,
                if served.h3 { " + h3/QUIC" } else { "" },
            );
            if !served.h3 {
                waitless::println!("[WARN] h3 disabled (QUIC/UDP bind failed)");
            }
        }
        Err(_) => waitless::println!("[WARN] https disabled (cert/key invalid)"),
    }
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

async fn handle_request(req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()> {
    // Streaming generated body: the handler **pushes** chunks via
    // `res.write()`. On h1 each chunk goes straight to the wire with TCP
    // backpressure, so peak memory stays O(chunk) — a 1 GiB body streams
    // fine on a 512 MiB VM, which buffering could not. h3 streams it too
    // (every h3 request gets a live `H3Sink`). h2 is the one exception:
    // `/stream` is a bodyless GET, and h2 dispatches those inline with a
    // sink-less `Response`, so `res.write` buffers the whole 1 GiB —
    // don't fetch the huge size over h2. (A bodied request streams on h2
    // too; see docs/streaming-response.md.)
    if req.path() == b"/stream" {
        res.content_type(b"application/octet-stream");
        let zeros = STATIC_64K_BYTES.get(); // 64 KiB of zeros, reused
        let mut remaining: usize = 1024 * 1024 * 1024;
        while remaining > 0 {
            let n = remaining.min(zeros.len());
            res.write(&zeros[..n]).await?;
            remaining -= n;
        }
        res.finish().await?;
        return Ok(());
    }
    // Streaming echo: write each request-body chunk straight back out as
    // the response body — plain handler code, no framework echo mode. On
    // h1 `req.read_chunk` and `res.write` share one connection (the serve
    // loop's RefCell duplex), so each chunk is read, then written to the
    // wire with backpressure: bounded O(chunk) over plaintext AND TLS.
    // `/echo` is a bodied request, so it's bounded on h2 (the spawned
    // per-stream `H2Sink`) and h3 (`H3Sink`) too. The same shape
    // expresses a proxy / transform.
    if req.path() == b"/echo" {
        let ct = req
            .header(b"content-type")
            .map(|v| v.to_vec())
            .unwrap_or_else(|| b"application/octet-stream".to_vec());
        res.content_type(ct);
        while let Some(chunk) = req.read_chunk().await {
            // Splice: move the received body IOBuf straight to the response —
            // no copy on the way out (full zero-copy on plain HTTP; one fewer
            // copy on TLS/h3, where the AEAD encrypt is the only transform).
            res.write(chunk.into_owned()).await?;
        }
        return res.finish().await;
    }
    // Body-consuming routes run first: they need `&mut req` for
    // `read_chunk`, so they can't sit inside a `match req.path()` whose
    // scrutinee holds an immutable borrow of `req` across the arms.
    if req.path() == b"/discard" {
        // `read_chunk().await` yields the next run of body bytes as a
        // `BodyChunkGuard` — a zero-copy view over the parse buffer's
        // leading prebuf or, past it, the transport's own RX buffer
        // (item H of docs/rx-path-optimizations.md). We don't look at
        // the bytes; just walking the stream advances the conn state
        // past the body so the next keep-alive request parses
        // correctly. `None` ends the body.
        while let Some(chunk) = req.read_chunk().await {
            core::hint::black_box(chunk.data().len());
        }
        res.set(Response::ok(b"application/json", b"{\"status\":\"discarded\"}"));
        return Ok(());
    }
    // E2E truth endpoint for the TCP client path (next-hop resolve →
    // ARP → SYN → first bytes). Prefix match: the target rides in the
    // query string, `/connect-probe?ip=A.B.C.D&port=N`. Async (it
    // awaits a connect with a deadline), so it can't sit inside the
    // sync `match` below.
    if let Some(query) = req.path().strip_prefix(b"/connect-probe") {
        let probe = connect_probe_response(query).await;
        res.set(probe);
        return Ok(());
    }
    // The h1-CLIENT truth endpoint: a real fetch (request writer →
    // response parser → body framing) over plain TCP or client TLS.
    // `/fetch-probe?ip=A.B.C.D&port=N[&path=/x][&tls=0|1][&pin=hex64]`.
    // Boxed: the fetch future stacks a whole client connection
    // (TLS client state pump + parser + body reader) — keeping it
    // inline would bloat EVERY handler invocation's state machine
    // (and the stack temporaries that build it) for the sake of a
    // cold dev probe. `Box::pin` confines that to the probe path.
    if let Some(query) = req.path().strip_prefix(b"/fetch-probe") {
        let probe = alloc::boxed::Box::pin(fetch_probe_response(query)).await;
        res.set(probe);
        return Ok(());
    }
    res.set(match req.path() {
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

        b"/quic_stats" => quic_stats_response(),
        b"/obs" => obs_response(),
        b"/compute" => {
            core::hint::black_box(compute_work());
            Response::ok(b"application/json", b"{\"status\":\"computed\"}")
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
    });
    Ok(())
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

