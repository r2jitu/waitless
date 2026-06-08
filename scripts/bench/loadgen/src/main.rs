// loadgen — Async TCP/TLS load generator for the unikernel
// benchmark suite. Replaces the Python `multiprocessing` paths
// for `tls_handshake_max` and `tcp_echo_max`, both of which were
// client-bound on Python's per-call overhead.
//
// Output format mirrors what `scripts/bench/cli.py` parses today:
//
//   RPS <number>
//   P50_US <number>
//   P99_US <number>
//
// Anything else on stdout is informational. Stderr is for logs.

use std::time::Duration;

use clap::{Parser, Subcommand};

mod gateway;
mod h3_echo;
mod h3_health;
mod h3_upload;
mod http_close;
mod http_load;
mod http_upload;
mod tcp_echo;
mod tls_handshake;
mod tls_resume;
mod tls_util;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    workload: Workload,
}

#[derive(Subcommand, Debug)]
enum Workload {
    /// Full TLS 1.3 handshake rate: open TCP, handshake, send one
    /// HTTP/1.1 GET, read the response, close. Each worker loops
    /// independently; results are aggregated across workers.
    /// Session resumption is disabled — every handshake is a fresh
    /// ECDHE + ECDSA P-256 sign. Use `tls-resume` for the resumption
    /// hot path.
    TlsHandshake {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "/health")]
        endpoint: String,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "1")]
        warmup_secs: u64,
        /// Number of independent worker tasks driving handshakes
        /// in parallel. The harness scales this with target cpus.
        #[arg(long, default_value = "4")]
        parallelism: usize,
    },
    /// TLS 1.3 session resumption rate. Each worker keeps its own
    /// ticket cache; the first handshake per worker is fresh
    /// (skipped from the histogram), subsequent handshakes resume
    /// via PSK-DHE. The server's flight skips Certificate +
    /// CertificateVerify, so this workload's RPS / p50 should sit
    /// well above `tls-handshake` once the server supports
    /// resumption.
    TlsResume {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "/health")]
        endpoint: String,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "1")]
        warmup_secs: u64,
        #[arg(long, default_value = "4")]
        parallelism: usize,
    },
    /// Plain HTTP throughput with fresh TCP per request — accept-rate
    /// bound, no crypto. Each worker loops: TCP connect, GET with
    /// `Connection: close`, drain response, close. Pairs with
    /// `tls-handshake` (same shape + crypto) to isolate the
    /// per-accept work from crypto cost.
    HttpClose {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "/health")]
        endpoint: String,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "1")]
        warmup_secs: u64,
        #[arg(long, default_value = "4")]
        parallelism: usize,
    },
    /// Bulk-RX upload: keep-alive HTTP/1.1 POST with sized body,
    /// tiny response, optionally over TLS. Each iteration sends
    /// ~msg_size/MSS RX segments to the server on the same 4-tuple
    /// — the shape that exercises driver RX path / RSC coalescing.
    HttpUpload {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "/discard")]
        endpoint: String,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "16")]
        connections: usize,
        #[arg(long, default_value = "32768")]
        msg_size: usize,
        /// Wrap each connection in TLS 1.3. Off by default (plain HTTP).
        #[arg(long, default_value = "false")]
        tls: bool,
    },
    /// TCP ping-pong throughput: open `connections` TCP streams,
    /// each sending an `msg_size` byte payload and waiting for the
    /// echoed response, in a tight loop. Latency samples come from
    /// connection 0 only to keep bookkeeping cheap.
    TcpEcho {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "16")]
        connections: usize,
        #[arg(long, default_value = "64")]
        msg_size: usize,
    },
    /// HTTP/3 keep-alive throughput. Each worker opens its own
    /// QUIC connection to the unikernel's H3 server, completes
    /// the handshake (skipped from the histogram), then fires
    /// sequential GET requests on the keep-alive connection.
    /// QUIC analogue of `health_tls_max` — measures the post-
    /// handshake AEAD + packet-encode + UDP-emit hot path that
    /// item B2 (encoder writes directly into the driver TX-pool
    /// slot) targets.
    H3Health {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "/health")]
        endpoint: String,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "1")]
        warmup_secs: u64,
        #[arg(long, default_value = "4")]
        parallelism: usize,
    },
    /// HTTP/3 bidirectional (RX+TX) echo throughput. Each worker
    /// opens its own QUIC connection and loops: POST `--body-bytes`
    /// to `/echo`, then read the full echoed response body back.
    /// Exercises BOTH directions per round-trip (QUIC RX reassembly
    /// of the upload + AEAD/encode/UDP-emit of the echo); a length
    /// mismatch or read error counts as a failure. Balanced twin of
    /// `h3-upload` (send-only) and `h3-health` (recv-only GET).
    H3Echo {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "/echo")]
        endpoint: String,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "1")]
        warmup_secs: u64,
        #[arg(long, default_value = "4")]
        parallelism: usize,
        /// Request body size in bytes (echoed back by the server).
        #[arg(long, default_value = "65536")]
        body_bytes: usize,
    },
    /// HTTP/3 upload-isolated (server-RX) throughput. Same POST as
    /// `h3-echo` but the rate reflects send-completion (request body
    /// fully written + FIN) — the response is drained-and-discarded
    /// after the latency is recorded, so the numbers isolate the
    /// QUIC RX / upload direction with minimal response handling.
    H3Upload {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "/echo")]
        endpoint: String,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "1")]
        warmup_secs: u64,
        #[arg(long, default_value = "4")]
        parallelism: usize,
        /// Request body size in bytes uploaded to the server.
        #[arg(long, default_value = "65536")]
        body_bytes: usize,
    },
    /// Unified keep-alive HTTP GET throughput across protocol
    /// versions — the keep-alive analogue of `wrk` (h1) and
    /// `h3-health` (h3), plus HTTP/2. `--proto h1|h2|h3` selects the
    /// version; `--connections` opens that many transport connections
    /// and `--streams` fires that many concurrent in-flight requests
    /// per connection (h2/h3 only — h1 is sequential keep-alive). Maps
    /// onto h2load's `-c` / `-m`. h2/h3 always run over TLS/QUIC; h1
    /// is TLS by default (`--plaintext` for cleartext HTTP).
    Http {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "/health")]
        endpoint: String,
        #[arg(long, value_enum, default_value = "h1")]
        proto: http_load::Proto,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        #[arg(long, default_value = "1")]
        warmup_secs: u64,
        /// Parallel transport connections (h2load `-c`).
        #[arg(long, default_value = "4")]
        connections: usize,
        /// Concurrent in-flight requests per connection (h2load `-m`);
        /// h2/h3 only — h1 forces 1 (sequential keep-alive).
        #[arg(long, default_value = "1")]
        streams: usize,
        /// Cleartext HTTP for h1 (no TLS). Ignored for h2/h3.
        #[arg(long, default_value = "false")]
        plaintext: bool,
    },
    /// API-gateway / sidecar ping-pong: drives the unikernel's
    /// `GATEWAY_PORT` listener, which on each request forwards a
    /// payload to a UDP backend, awaits the reply, and returns it.
    /// We host the backend in this same loadgen process (a tokio
    /// UDP echo task on `backend_port`) so a single binary owns
    /// both the load and the downstream service. The unikernel
    /// reaches us via `Net::gateway()` (DHCP-discovered host IP),
    /// or via 127.0.0.1 in the native build. This is the workload
    /// where async + a syscall-free datapath compound: every
    /// in-flight request is parked on a UDP recv waker, each conn
    /// does ~4 packet round-trips through the stack, and a Linux+
    /// Tokio equivalent (which the native backend approximates)
    /// pays ~5 syscalls per request just to push bytes.
    Gateway {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        /// Where the loadgen's UDP echo backend listens. The
        /// unikernel sends datagrams here and awaits the reply.
        #[arg(long, default_value = "7777")]
        backend_port: u16,
        #[arg(long, default_value = "5")]
        duration_secs: u64,
        /// Concurrent TCP keep-alive connections driving the
        /// unikernel. Each conn does a tight ping-pong loop;
        /// every request transitions through the unikernel's
        /// async runtime + UDP backend hop.
        #[arg(long, default_value = "64")]
        connections: usize,
        /// Wire payload size per request. Must match the
        /// unikernel's `GATEWAY_MSG_SIZE`.
        #[arg(long, default_value = "32")]
        msg_size: usize,
    },
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    // rustls 0.23 wants the ring crypto provider installed once at
    // startup. Cheap; no-op if already done.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let result = match args.workload {
        Workload::TlsHandshake {
            host,
            port,
            endpoint,
            duration_secs,
            warmup_secs,
            parallelism,
        } => runtime.block_on(tls_handshake::run(
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            Duration::from_secs(warmup_secs),
            parallelism,
        )),
        Workload::TlsResume {
            host,
            port,
            endpoint,
            duration_secs,
            warmup_secs,
            parallelism,
        } => runtime.block_on(tls_resume::run(
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            Duration::from_secs(warmup_secs),
            parallelism,
        )),
        Workload::H3Health {
            host,
            port,
            endpoint,
            duration_secs,
            warmup_secs,
            parallelism,
        } => runtime.block_on(h3_health::run(
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            Duration::from_secs(warmup_secs),
            parallelism,
        )),
        Workload::H3Echo {
            host,
            port,
            endpoint,
            duration_secs,
            warmup_secs,
            parallelism,
            body_bytes,
        } => runtime.block_on(h3_echo::run(
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            Duration::from_secs(warmup_secs),
            parallelism,
            body_bytes,
        )),
        Workload::H3Upload {
            host,
            port,
            endpoint,
            duration_secs,
            warmup_secs,
            parallelism,
            body_bytes,
        } => runtime.block_on(h3_upload::run(
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            Duration::from_secs(warmup_secs),
            parallelism,
            body_bytes,
        )),
        Workload::HttpClose {
            host,
            port,
            endpoint,
            duration_secs,
            warmup_secs,
            parallelism,
        } => runtime.block_on(http_close::run(
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            Duration::from_secs(warmup_secs),
            parallelism,
        )),
        Workload::TcpEcho {
            host,
            port,
            duration_secs,
            connections,
            msg_size,
        } => runtime.block_on(tcp_echo::run(
            &host,
            port,
            Duration::from_secs(duration_secs),
            connections,
            msg_size,
        )),
        Workload::HttpUpload {
            host,
            port,
            endpoint,
            duration_secs,
            connections,
            msg_size,
            tls,
        } => runtime.block_on(http_upload::run(
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            connections,
            msg_size,
            tls,
        )),
        Workload::Http {
            host,
            port,
            endpoint,
            proto,
            duration_secs,
            warmup_secs,
            connections,
            streams,
            plaintext,
        } => runtime.block_on(http_load::run(
            proto,
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            Duration::from_secs(warmup_secs),
            connections,
            streams,
            plaintext,
        )),
        Workload::Gateway {
            host,
            port,
            backend_port,
            duration_secs,
            connections,
            msg_size,
        } => runtime.block_on(gateway::run(
            &host,
            port,
            backend_port,
            Duration::from_secs(duration_secs),
            connections,
            msg_size,
        )),
    };

    print_result(result);
    Ok(())
}

/// Aggregated workload result. The harness reads RPS / P50_US /
/// P99_US off stdout; everything else is informational.
pub struct WorkloadResult {
    pub ops: u64,
    pub elapsed: Duration,
    pub p50_us: u64,
    pub p99_us: u64,
}

fn print_result(r: WorkloadResult) {
    let secs = r.elapsed.as_secs_f64().max(1e-6);
    println!("RPS {:.3}", r.ops as f64 / secs);
    println!("P50_US {}", r.p50_us);
    println!("P99_US {}", r.p99_us);
}
