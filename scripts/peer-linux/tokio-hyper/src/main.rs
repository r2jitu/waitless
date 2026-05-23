// tokio-hyper-peer — the "handler-parity" baseline for the waitless
// Pareto-frontier bench. Same handlers, same response bodies as
// `apps/webserver/src/main.rs`, served over a tokio + hyper + rustls
// + axum stack on Linux. Pairs with the nginx peer:
//
//   nginx peer    : "what real ops compares against" (battle-tested,
//                   kTLS, syscall-tax exposed)
//   tokio-hyper   : "what's the handler vs the OS contribution"
//                   (same Rust/tokio ecosystem as waitless's app code,
//                   isolates the OS overhead from the handler tightness)
//
// Listens on:
//   :80  — plain HTTP, same as waitless HTTP_PORT
//   :443 — HTTPS over rustls, same as waitless HTTPS_PORT
//   :8080 — plain HTTP upstream for nginx peer to proxy /compute and
//          /discard to. Same binary serves all three.

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use clap::Parser;
use http_body_util::BodyExt;
use tower_http::limit::RequestBodyLimitLayer;

// ── Static response bodies (byte-mirror of apps/webserver/src/endpoints.rs) ──
//
// `&'static [u8]` for everything — axum's `Bytes::from_static` is a
// zero-copy view into rodata. No per-request allocation, matching
// waitless's `IOBuf::from_static`.

const HEALTH_JSON: &[u8] = b"{\"status\":\"ok\",\"runtime\":\"waitless\",\"version\":\"0.1.0\"}";
const COMPUTED_JSON: &[u8] = b"{\"status\":\"computed\"}";
const DISCARDED_JSON: &[u8] = b"{\"status\":\"discarded\"}";

// 16 KiB / 64 KiB / 256 KiB / 1 MiB of zeros. Sized via const generics
// the same way waitless does it (`ZeroBody<N>`). Static `[0u8; N]` lands
// in .rodata; we want that — bench measures the wire path, not the
// page-allocator.
const STATIC_16K: &[u8; 16 * 1024] = &[0u8; 16 * 1024];
const STATIC_64K: &[u8; 64 * 1024] = &[0u8; 64 * 1024];
const STATIC_256K: &[u8; 256 * 1024] = &[0u8; 256 * 1024];
const STATIC_1M: &[u8; 1024 * 1024] = &[0u8; 1024 * 1024];

// MIME constants pre-built as HeaderValue so the per-request response
// builder skips the str → HeaderValue parse.
const CT_JSON: HeaderValue = HeaderValue::from_static("application/json");
const CT_OCTET: HeaderValue = HeaderValue::from_static("application/octet-stream");

// ── Compute-bound handler — byte-identical FNV-1a-shape loop ───
//
// Mirrors `compute_work()` in apps/webserver/src/main.rs:449. Seed +
// prime match exactly. `core::hint::black_box` keeps LLVM from folding
// the loop away.

fn compute_work() -> u32 {
    let mut h: u32 = 2_166_136_261;
    for i in 0..100_000u32 {
        h ^= i;
        h = h.wrapping_mul(16_777_619);
    }
    h
}

// ── Handlers ───────────────────────────────────────────────────

async fn health() -> Response {
    static_response(CT_JSON, Bytes::from_static(HEALTH_JSON))
}

async fn static_16k() -> Response {
    static_response(CT_OCTET, Bytes::from_static(STATIC_16K))
}
async fn static_64k() -> Response {
    static_response(CT_OCTET, Bytes::from_static(STATIC_64K))
}
async fn static_256k() -> Response {
    static_response(CT_OCTET, Bytes::from_static(STATIC_256K))
}
async fn static_1m() -> Response {
    static_response(CT_OCTET, Bytes::from_static(STATIC_1M))
}

async fn compute() -> Response {
    std::hint::black_box(compute_work());
    static_response(CT_JSON, Bytes::from_static(COMPUTED_JSON))
}

async fn discard(req: Request) -> Response {
    // Drain the body in chunks, drop them. Mirrors waitless's
    // `while let Some(chunk) = body.chunk().await` loop — the wire
    // bytes flow through without ever sitting in a single contiguous
    // buffer past the per-frame size.
    let mut body = req.into_body();
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(f) => {
                if let Some(data) = f.data_ref() {
                    std::hint::black_box(data.len());
                }
            }
            Err(_) => break,
        }
    }
    static_response(CT_JSON, Bytes::from_static(DISCARDED_JSON))
}

fn static_response(content_type: HeaderValue, body: Bytes) -> Response {
    let mut h = HeaderMap::with_capacity(2);
    h.insert(header::CONTENT_TYPE, content_type);
    // Content-Length is set by axum/hyper from the Body's known size.
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = StatusCode::OK;
    *resp.headers_mut() = h;
    resp
}

// ── Router + main ──────────────────────────────────────────────

fn build_router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/static-16k", get(static_16k))
        .route("/static-64k", get(static_64k))
        .route("/static-256k", get(static_256k))
        .route("/static-1m", get(static_1m))
        .route("/compute", get(compute))
        // POST /discard. 16 MiB body cap matches what nginx will
        // forward to us via client_max_body_size.
        .route("/discard", post(discard))
        .layer(RequestBodyLimitLayer::new(16 * 1024 * 1024))
}

#[derive(Parser, Debug)]
struct Args {
    /// Plain HTTP port. 0 disables.
    #[arg(long, default_value = "80")]
    http_port: u16,
    /// HTTPS port. 0 disables.
    #[arg(long, default_value = "443")]
    https_port: u16,
    /// Sidecar plain HTTP port for nginx upstream. 0 disables.
    #[arg(long, default_value = "8080")]
    upstream_port: u16,
    /// PEM cert path (for HTTPS).
    #[arg(long, default_value = "/etc/tokio-hyper/tls/dev_cert.pem")]
    cert: PathBuf,
    /// PEM key path (for HTTPS).
    #[arg(long, default_value = "/etc/tokio-hyper/tls/dev_key.pem")]
    key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // rustls 0.23 wants the ring crypto provider installed once at
    // startup. Cheap; no-op if already done.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args = Args::parse();
    let app = build_router();

    let mut joins: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if args.http_port != 0 {
        let app = app.clone();
        let addr = SocketAddr::from(([0, 0, 0, 0], args.http_port));
        tracing::info!("listen http://{}", addr);
        joins.push(tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        }));
    }

    if args.upstream_port != 0 && args.upstream_port != args.http_port {
        let app = app.clone();
        let addr = SocketAddr::from(([127, 0, 0, 1], args.upstream_port));
        tracing::info!("listen http://{} (nginx upstream)", addr);
        joins.push(tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        }));
    }

    if args.https_port != 0 {
        let app = app.clone();
        let addr = SocketAddr::from(([0, 0, 0, 0], args.https_port));
        let cert_pem = std::fs::read(&args.cert)?;
        let key_pem = std::fs::read(&args.key)?;
        let config =
            axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;
        tracing::info!("listen https://{}", addr);
        joins.push(tokio::spawn(async move {
            axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service())
                .await
                .unwrap();
        }));
    }

    // Run until SIGINT / SIGTERM.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    for j in joins {
        j.abort();
    }
    Ok(())
}
