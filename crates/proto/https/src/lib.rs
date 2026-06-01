// crates/proto/https — the all-transports HTTPS facade.
//
// `https::serve` brings up a full HTTPS site in one call: HTTP/1.1 + h2
// over TLS/TCP (`http2::listen`) **and** h3 over QUIC/UDP
// (`http3::listen`) on the same port, with `Alt-Svc` advertising h3 to
// HTTP/1.1- and HTTP/2-speaking clients. h3 is best-effort: if the UDP
// bind fails the TCP server still comes up (and the Alt-Svc header is
// suppressed). This is the layer where "HTTPS = all secure versions"
// actually lives — the per-transport listeners (`http2::listen`,
// `http3::listen`) remain available for finer control.
//
// One handler serves every transport via the [`Service`] trait. The
// trait's `handle` method is **generic over the byte stream**, which is
// what lets a single value drive both transports: the TCP path
// monomorphizes `handle::<http2::TlsStream>`, the QUIC path
// `handle::<http::NullStream>`. (A plain `async fn` handler can't do
// this — one value can't be two stream-monomorphizations at once — so
// the polymorphism moves into the trait method. See `docs/crates.md`.)

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use http::{BodyReader, HttpStream, NullStream, Request, Response};

/// A request handler that serves any HTTP version over any transport.
///
/// `handle` is generic over the byte stream `S` so one `Service` value
/// can be driven by every transport the facade binds — the TCP/TLS path
/// instantiates it with `http2::TlsStream`, the QUIC path with
/// `http::NullStream`. Implement it once (typically forwarding to a
/// stream-generic free function) and hand it to [`serve`].
///
/// ```ignore
/// #[derive(Clone, Copy)]
/// struct Site;
/// impl https::Service for Site {
///     async fn handle<S: http::HttpStream>(
///         &self,
///         req: &http::Request,
///         body: &mut http::BodyReader<'_, S>,
///     ) -> http::Response {
///         my_router(req, body).await
///     }
/// }
/// https::serve(443, Site, CERT_CHAIN, KEY_DER)?;
/// ```
pub trait Service: Send + Sync + 'static {
    /// Handle one request. Borrows the request and a `BodyReader` over
    /// whatever transport stream `S` the active listener uses.
    ///
    /// The returned future is intentionally **not** `Send`-bounded: the
    /// listeners run each connection on its owning worker (the per-conn
    /// future is `!Send` by design — `BodyReader<S>` borrows per-worker
    /// transport state), so requiring a `Send` future here would make
    /// the trait unimplementable. The `Service` *value* is `Send + Sync`
    /// (it's shared across workers via `Arc`); the work it produces is
    /// not.
    fn handle<S: HttpStream>(
        &self,
        req: &Request,
        body: &mut BodyReader<'_, S>,
    ) -> impl core::future::Future<Output = Response>;
}

/// Failure from [`serve`]. Only the TCP/TLS half is fatal — h3 is
/// best-effort, so a QUIC bind failure is swallowed (the site still
/// serves over TCP, just without advertising h3).
#[derive(Debug)]
pub enum Error {
    /// The HTTP/1.1 + h2 listener (the required half) failed to bind.
    Tcp(http2::ListenError),
}

/// Serve `service` as a full HTTPS site on `port`: h1.1 + h2 over
/// TLS/TCP and h3 over QUIC/UDP, with automatic `Alt-Svc`. `cert_chain`
/// (DER, leaf first) + `key_der` are the same blobs the per-transport
/// listeners accept.
pub fn serve<Sv: Service>(
    port: u16,
    service: Sv,
    cert_chain: &'static [&'static [u8]],
    key_der: &'static [u8],
) -> Result<(), Error> {
    let service = Arc::new(service);

    // Bring up h3 (QUIC/UDP) first, best-effort — its success gates the
    // Alt-Svc advertisement on the TCP path. `handle::<NullStream>`:
    // h3 reassembles the body and hands a prebuffered BodyReader.
    let svc_h3 = Arc::clone(&service);
    let h3_up = http3::listen(
        port,
        async move |req: Request, body: &mut BodyReader<'_, NullStream>| -> Response {
            svc_h3.handle(&req, body).await
        },
        cert_chain,
        key_der,
    )
    .is_ok();

    // Build the Alt-Svc value once (advertises h3 on the same port);
    // suppressed when h3 didn't come up.
    let alt: Option<&'static [u8]> = if h3_up { Some(alt_svc_value(port)) } else { None };

    // h1.1 + h2 over TLS/TCP — the required half.
    // `handle::<http2::TlsStream>`: the live TLS stream.
    let svc_tcp = Arc::clone(&service);
    http2::listen(
        port,
        async move |req: &Request, body: &mut BodyReader<'_, http2::TlsStream>| -> Response {
            let resp = svc_tcp.handle(req, body).await;
            match alt {
                Some(a) => resp.with_header(&b"Alt-Svc"[..], a),
                None => resp,
            }
        },
        cert_chain,
        key_der,
    )
    .map_err(Error::Tcp)?;

    Ok(())
}

/// Build the `Alt-Svc: h3=":<port>"; ma=86400` value as a leaked
/// `'static` slice (one-shot at listen time; the TCP handler reads it
/// per response as a borrowed-static, zero per-request alloc).
fn alt_svc_value(port: u16) -> &'static [u8] {
    let mut buf: Vec<u8> = Vec::with_capacity(24);
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
    Box::leak(buf.into_boxed_slice())
}
