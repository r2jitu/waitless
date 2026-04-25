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

use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

mod tcp_echo;
mod tls_handshake;

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
            host, port, endpoint, duration_secs, warmup_secs, parallelism,
        } => runtime.block_on(tls_handshake::run(
            &host,
            port,
            &endpoint,
            Duration::from_secs(duration_secs),
            Duration::from_secs(warmup_secs),
            parallelism,
        )),
        Workload::TcpEcho {
            host, port, duration_secs, connections, msg_size,
        } => runtime.block_on(tcp_echo::run(
            &host,
            port,
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

/// Convenience: run `body` until `deadline` and return how many
/// times it succeeded plus the latency samples it produced. Used
/// by both workloads under the hood.
#[allow(dead_code)]
pub async fn loop_until<F, Fut>(deadline: Instant, mut body: F) -> u64
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut count = 0u64;
    while Instant::now() < deadline {
        if body().await {
            count += 1;
        }
    }
    count
}
