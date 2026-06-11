// Waitless Example: Reverse-Proxy / API Gateway
//
// The canonical "my handler calls a database / another service"
// pattern, and the showcase for the client roles. The front door is
// plain HTTP on :80; on every request the handler makes ONE outbound
// HTTP/1.1 GET to a backend over the HTTP client (`http::client::get`)
// and relays the backend's status + body back to the caller. The
// outbound fetch is the whole point — the handler suspends on it like
// any other await, and the per-core event loop keeps serving other
// connections while this one is parked on the backend round-trip.
//
// Contrast //apps/hello (one static response) and //apps/webserver
// (TLS, h2/h3, many routes). This example stays deliberately small so
// the outbound-fetch flow is the only thing to read.

#![no_std]

extern crate alloc;

use http::{Request, Response};
use waitless::net::Net;

// ---- Backend configuration --------------------------------------------------
//
// The single upstream this gateway proxies to. EDIT THESE for your
// own backend. The benchmark harness bakes the peer's IP in here (the
// second loadgen VM's address) so the proxied path can be measured
// against a real upstream; for a local demo, point it at any HTTP/1.1
// server reachable from the guest (e.g. the QEMU host gateway).
//
// No TLS on the outbound leg — this is the minimal example. The TLS
// variant is `https::client::get` (ALPN h2/h1.1) / `https::client::get_h1`
// (pinned h1.1); swapping `BACKEND` to a `Net::up()`-derived gateway IP
// + one of those calls is all it takes to proxy to an HTTPS upstream.
const BACKEND_IP: [u8; 4] = [10, 0, 0, 2];
const BACKEND_PORT: u16 = 80;
const BACKEND_PATH: &[u8] = b"/";
/// `Host` header sent upstream. Most backends ignore it for a single
/// vhost; set it to the upstream's expected name if it routes by Host.
const BACKEND_HOST: &[u8] = b"backend";

/// Cap on the backend response body we'll buffer and relay (256 KiB).
/// `http::client::get` returns `Err(Body(TooLarge))` past this — we
/// answer 502 rather than letting one upstream balloon our heap.
const BODY_CAP: usize = 256 * 1024;

/// Deadline for the whole outbound exchange (connect + request +
/// response). A wedged backend must not pin this connection forever.
const FETCH_DEADLINE_US: u64 = 5_000_000; // 5 s

// ---- Boot -------------------------------------------------------------------

#[waitless::init]
async fn init() {
    Net::up().await.expect("Net::up failed");
    http::listen(80, gateway).expect("http bind");
    waitless::println!(
        "listen tcp://:80 (gateway -> http://{}.{}.{}.{}:{}{})",
        BACKEND_IP[0],
        BACKEND_IP[1],
        BACKEND_IP[2],
        BACKEND_IP[3],
        BACKEND_PORT,
        core::str::from_utf8(BACKEND_PATH).unwrap_or("/"),
    );
}

// ---- Handler ----------------------------------------------------------------

/// One handler, two routes:
///   * `GET /health` — static 200, never touches the backend (liveness
///     probes + the bench harness's readiness check).
///   * everything else — proxy: one outbound GET to the backend, relay
///     its status + body.
async fn gateway(req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()> {
    if req.path() == b"/health" {
        res.set(Response::ok(b"application/json", b"{\"status\":\"ok\"}"));
        return Ok(());
    }

    // The outbound fetch stacks a whole client connection (TCP connect
    // + response parser + body reader) into its future, so box it to
    // keep the handler's own state machine small (the webserver's
    // /fetch-probe boxes its fetch for the same reason).
    let fetched = alloc::boxed::Box::pin(proxy_to_backend()).await;

    match fetched {
        // Relay the backend's status + body verbatim. We forward the
        // upstream Content-Type when it sent one, else fall back to
        // octet-stream. `Response::ok` builds a 200; `status()` then
        // stamps the real upstream code over it.
        Some((status, content_type, body)) => {
            res.set(Response::ok(content_type, body));
            res.status(status as i32);
            Ok(())
        }
        // Any failure on the outbound leg (connect refused, timeout,
        // malformed response, body over cap) is a Bad Gateway.
        None => {
            res.set(Response::ok(b"text/plain", &b"502 Bad Gateway: backend fetch failed\n"[..]));
            res.status(502);
            Ok(())
        }
    }
}

/// Issue the one outbound HTTP/1.1 GET to the backend, under a
/// deadline. `Some((status, content_type, body))` on success; `None`
/// on any failure (connect, fetch, body-read, or the deadline firing).
async fn proxy_to_backend() -> Option<(u16, alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)> {
    use waitless::runtime::{IpAddr, Ipv4Addr};
    let [a, b, c, d] = BACKEND_IP;
    let ip = IpAddr::V4(Ipv4Addr::from(a, b, c, d));

    // `timeout_us` returns `None` if the inner future doesn't finish in
    // time; `Some(inner)` otherwise. `http::client::get` connects,
    // sends one `Connection: close` GET, parses the response head and
    // reads the body into a bounded `Vec` (<= BODY_CAP), returning
    // `(ResponseHead, Vec<u8>)` or a `GetError` naming the failing
    // stage (Connect / Fetch / Body).
    let got =
        waitless::runtime::timeout_us(FETCH_DEADLINE_US, http::client::get(ip, BACKEND_PORT, BACKEND_HOST, BACKEND_PATH, BODY_CAP))
            .await?;
    let (head, body) = got.ok()?;

    // Carry the upstream Content-Type forward when present.
    let content_type = head
        .header(b"content-type")
        .map(|v| v.to_vec())
        .unwrap_or_else(|| b"application/octet-stream".to_vec());
    Some((head.status, content_type, body))
}
