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
// One **plain** handler serves every transport. The handler signature —
// `(&Request, &mut BodyReader<'_>)` — is transport-erased (the request
// body reaches it through `http`'s `&mut dyn BodySource` seam, not a
// stream type parameter), so a single value drives h1.1/h2 over TLS and
// h3 over QUIC alike. No `Service` trait, no per-protocol adapter: the
// facade just hands the same (`Arc`-shared) handler to both listeners,
// wrapping the TCP path to append `Alt-Svc`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use http::{Request, Response};

/// Outcome of a successful [`serve`]. The TCP/TLS server is always up
/// (otherwise `serve` returns `Err`); `h3` reports whether the QUIC/UDP
/// listener *also* came up, so the caller can log it.
#[derive(Debug, Clone, Copy)]
pub struct Served {
    /// `true` when h3 (QUIC/UDP) bound and is being advertised via
    /// `Alt-Svc`; `false` when the UDP bind failed (TCP still serving,
    /// just without an h3 upgrade offer).
    pub h3: bool,
}

/// Failure from [`serve`]. Only the TCP/TLS half is fatal — h3 is
/// best-effort, and its bind failure is reported via [`Served::h3`]
/// rather than as an error.
#[derive(Debug)]
pub enum ServeError {
    /// The HTTP/1.1 + h2 listener (the required half) failed to bind.
    Tcp(http2::ListenError),
}

/// Serve `handler` as a full HTTPS site on `port`: h1.1 + h2 over
/// TLS/TCP and h3 over QUIC/UDP, with automatic `Alt-Svc`. `cert_chain`
/// (DER, leaf first) + `key_der` are the same blobs the per-transport
/// listeners accept.
///
/// `handler` is any async `fn`/closure taking `(&Request, &mut
/// BodyReader<'_>)` — the same shape `http::listen` takes — so one
/// handler can drive plain HTTP, HTTPS, and HTTP/3 with no per-version
/// wrapper.
pub fn serve<H>(
    port: u16,
    handler: H,
    cert_chain: &'static [&'static [u8]],
    key_der: &'static [u8],
) -> Result<Served, ServeError>
where
    H: for<'a, 'b> AsyncFn(&'a mut Request<'b>, &'a mut Response) -> Result<(), ()> + Send + Sync + 'static,
{
    // One handler, shared across both transports' per-conn tasks.
    let handler = Arc::new(handler);

    // Bring up h3 (QUIC/UDP) first, best-effort — its success gates the
    // Alt-Svc advertisement on the TCP path.
    let h3 = Arc::clone(&handler);
    let h3_up = http3::listen(
        port,
        async move |req: &mut Request<'_>, res: &mut Response| -> Result<(), ()> {
            (*h3)(req, res).await
        },
        cert_chain,
        key_der,
    )
    .is_ok();

    // Build the Alt-Svc value once (advertises h3 on the same port);
    // suppressed when h3 didn't come up.
    let alt: Option<&'static [u8]> = if h3_up { Some(alt_svc_value(port)) } else { None };

    // h1.1 + h2 over TLS/TCP — the required half. Wrap the handler to
    // append `Alt-Svc` so plain/H2 clients learn about the h3 endpoint.
    let tcp = Arc::clone(&handler);
    http2::listen(
        port,
        async move |req: &mut Request<'_>, res: &mut Response| -> Result<(), ()> {
            let r = (*tcp)(req, res).await;
            // Append Alt-Svc so plain/H2 clients learn the h3 endpoint.
            // Phase 0 buffers the response, so the head isn't on the wire
            // yet — setting it here is fine. (A streaming sink, later
            // phase, must set Alt-Svc before the first body byte.)
            if let Some(a) = alt {
                res.header(&b"Alt-Svc"[..], a);
            }
            r
        },
        cert_chain,
        key_der,
    )
    .map_err(ServeError::Tcp)?;

    Ok(Served { h3: h3_up })
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
