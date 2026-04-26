// Gateway / sidecar ping-pong workload.
//
// Drives the unikernel's gateway listener, which on each TCP
// request forwards a payload to a UDP backend, awaits the reply,
// and writes the reply back over TCP. The backend lives inside
// this same loadgen process (a tokio UDP echo task) so one binary
// owns both load and downstream service.
//
// Everything below uses tokio futures — UDP recv/send, TCP
// connect/read/write, the start barrier, and the cancellation
// token are all async. The driver task count (`connections`) is
// the headline knob: at 64+ conns each parked on its own backend
// recv at any given instant, the unikernel's async runtime
// juggles them per-worker, which is the win this workload
// measures.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Barrier;

use crate::WorkloadResult;

pub async fn run(
    host: &str,
    port: u16,
    backend_port: u16,
    duration: Duration,
    connections: usize,
    msg_size: usize,
) -> WorkloadResult {
    // Spin up the UDP echo backend the unikernel will fan out to.
    // Bind on the wildcard so the unikernel can reach us via the
    // gateway / host IP it discovered at DHCP time. `0.0.0.0` is
    // wrong on macOS hosts that have multiple interfaces — we let
    // the OS pick the routing source, which works for all our
    // bench environments (HVF, QEMU NAT, KVM tap, native loopback).
    let backend_addr: SocketAddr = format!("0.0.0.0:{backend_port}").parse().unwrap();
    let backend = match UdpSocket::bind(backend_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("loadgen gateway: backend bind {backend_port} failed: {e}");
            return WorkloadResult {
                ops: 0,
                elapsed: duration,
                p50_us: 0,
                p99_us: 0,
            };
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let backend_task = tokio::spawn(echo_loop(Arc::clone(&backend), Arc::clone(&stop)));

    // Driver tasks: open `connections` keep-alive TCP streams to
    // the unikernel's gateway listener, hold them at a start
    // barrier, then ping-pong as fast as each can. Latency from
    // task 0 only — bookkeeping at this rate isn't free.
    let host: Arc<str> = Arc::from(host.to_string().into_boxed_str());
    let payload: Arc<[u8]> = Arc::from(vec![b'g'; msg_size].into_boxed_slice());
    let barrier = Arc::new(Barrier::new(connections + 1));

    let mut handles = Vec::with_capacity(connections);
    for i in 0..connections {
        let host = Arc::clone(&host);
        let payload = Arc::clone(&payload);
        let barrier = Arc::clone(&barrier);
        let sample_latency = i == 0;
        handles.push(tokio::spawn(driver(
            host,
            port,
            payload,
            barrier,
            duration,
            sample_latency,
        )));
    }

    barrier.wait().await;
    let start = Instant::now();

    let mut total = 0u64;
    let mut combined = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();
    for h in handles {
        if let Ok((c, hist)) = h.await {
            total += c;
            combined.add(hist).ok();
        }
    }
    let elapsed = start.elapsed();

    stop.store(true, Ordering::Release);
    // Nudge the backend out of its blocking recv: send ourselves
    // a zero-byte datagram. Cheap and keeps the shutdown path
    // free of `tokio-util` deps.
    if let Ok(self_sock) = UdpSocket::bind("0.0.0.0:0").await {
        let _ = self_sock
            .send_to(&[], format!("127.0.0.1:{backend_port}"))
            .await;
    }
    let _ = backend_task.await;

    let p50 = combined.value_at_quantile(0.50);
    let p99 = combined.value_at_quantile(0.99);
    WorkloadResult {
        ops: total,
        elapsed,
        p50_us: p50,
        p99_us: p99,
    }
}

/// UDP echo loop. Reads one datagram, writes the same bytes back
/// to the sender, repeats until `stop` is set. The empty-datagram
/// kick from the outer task wakes us out of a blocking recv —
/// then `stop` is observed and we return.
async fn echo_loop(sock: Arc<UdpSocket>, stop: Arc<AtomicBool>) {
    let mut buf = [0u8; 2048];
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        if n == 0 {
            // Shutdown kick. Loop back, observe `stop`, exit.
            continue;
        }
        let _ = sock.send_to(&buf[..n], src).await;
    }
}

async fn driver(
    host: Arc<str>,
    port: u16,
    payload: Arc<[u8]>,
    barrier: Arc<Barrier>,
    duration: Duration,
    sample_latency: bool,
) -> (u64, Histogram<u64>) {
    let hist_zero = || Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap();

    let mut sock = match TcpStream::connect((&*host, port)).await {
        Ok(s) => s,
        Err(_) => {
            barrier.wait().await;
            return (0, hist_zero());
        }
    };
    let _ = sock.set_nodelay(true);

    let mut buf = vec![0u8; payload.len()];
    let mut hist = hist_zero();

    barrier.wait().await;
    let deadline = Instant::now() + duration;

    let mut count = 0u64;
    while Instant::now() < deadline {
        let t0 = if sample_latency {
            Some(Instant::now())
        } else {
            None
        };
        if sock.write_all(&payload).await.is_err() {
            break;
        }
        if sock.read_exact(&mut buf).await.is_err() {
            break;
        }
        if let Some(t0) = t0 {
            let us = t0.elapsed().as_micros() as u64;
            let _ = hist.record(us.max(1));
        }
        count += 1;
    }
    (count, hist)
}
