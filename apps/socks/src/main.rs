// Waitless Example: SOCKS5 Proxy (the flagship)
//
// A *generic* TCP proxy. Unlike //apps/gateway (which proxies every
// request to one hardcoded backend), this app has no destination of
// its own — it takes the target ip:port from the SOCKS5 protocol the
// client speaks, dials it with the TCP client (`tcp_connect`), and then
// relays bytes both ways until either side closes. It is the showcase
// for two things at once:
//
//   * the CLIENT role — `tcp_connect` does an active open to an
//     arbitrary peer the *protocol* chose (not us), and
//   * async I/O concurrency — the bidirectional relay parks on TWO
//     reads at once; while this connection waits on either side, the
//     per-core event loop keeps serving every other proxied flow. One
//     core, thousands of parked relays, no threads.
//
// Scope: SOCKS5 (RFC 1928), CONNECT command, IPv4 targets, no auth.
// That is exactly what `curl --socks5`, `ssh -D`, and a browser's
// SOCKS proxy setting need for IP-literal targets. Hostname targets
// (ATYP=domain) are rejected with the correct reply code — see the
// request handler — because no DNS resolver is built yet; clients
// should resolve locally (`curl --socks5`, NOT `--socks5-hostname`).
//
// The wire parsing (greeting + request byte layout, reply codes) lives
// in `socks5.rs` as pure functions with host unit tests; this file owns
// the async reads/writes and the relay.

#![no_std]

extern crate alloc;

// The SOCKS5 wire parsing lives in its own tiny crate (`//apps/socks:socks5`)
// so it can carry host unit tests (`socks5_test`) while staying pure —
// no waitless runtime, no I/O. This file owns the async reads/writes.
use socks5::{GreetingError, RequestError, Target};
use waitless::net::Net;
use waitless::runtime::{
    Either, IOBufChain, IpAddr, Ipv4Addr, TcpStream, select, tcp_connect, timeout_us,
};

// ---- Tunables ---------------------------------------------------------------

/// Front-door port. SOCKS5 runs over plain TCP; 1080 is the IANA
/// registered SOCKS port and the default every client assumes.
const LISTEN_PORT: u16 = 1080;

/// Deadline for the SOCKS5 handshake (greeting + request + connect).
/// A client that opens the TCP connection and then says nothing must
/// not pin a connection slot forever — close it after this.
const HANDSHAKE_DEADLINE_US: u64 = 10_000_000; // 10 s

/// Deadline for the outbound `tcp_connect` to the target. Separate from
/// the handshake budget so a slow/black-holed target reports the right
/// reply code (host-unreachable) promptly rather than hanging.
const CONNECT_DEADLINE_US: u64 = 5_000_000; // 5 s

/// Idle ceiling on the relay: if NEITHER direction moves a byte for
/// this long, tear the flow down. A live download/upload keeps
/// resetting it (every chunk is progress); only a wedged pair trips it.
const RELAY_IDLE_US: u64 = 120_000_000; // 120 s

// ---- Boot -------------------------------------------------------------------

#[waitless::init]
async fn init() {
    Net::up().await.expect("Net::up failed");
    // The SOCKS front door is raw TCP — no HTTP, no TLS. Every accepted
    // connection runs `socks` on the accepting core; the handler owns
    // that connection for its whole life.
    waitless::tcp_listen(LISTEN_PORT, socks).expect("socks bind");
    waitless::println!("listen tcp://:{} (socks5 CONNECT proxy, IPv4 targets)", LISTEN_PORT);
}

// ---- Per-connection handler -------------------------------------------------

/// One accepted SOCKS5 client. Drives the handshake, dials the target,
/// then relays. `client` (and any `target` we open) close on drop, so
/// every early `return` below is a clean teardown — `TcpStream::Drop`
/// RSTs/closes the connection. Untrusted input throughout: a SOCKS
/// client can send anything, so we read defensively and never panic.
async fn socks(mut client: TcpStream) {
    // The whole handshake runs under one deadline (`timeout_us` →
    // `None` if the client stalls). We only proceed to the relay on the
    // one happy nesting — `Some(Ok(Some(target)))`, i.e. the deadline
    // held, the handshake succeeded, and it produced a connected
    // upstream. Every other shape is a clean teardown:
    //   * outer `None`       — handshake deadline fired,
    //   * `Some(Err(()))`    — malformed / early-closed client,
    //   * `Some(Ok(None))`   — we sent a SOCKS failure reply and closed.
    // `client` (and `target`, when present) close on drop at the end.
    if let Some(Ok(Some(mut target))) =
        timeout_us(HANDSHAKE_DEADLINE_US, handshake(&mut client)).await
    {
        relay(&mut client, &mut target).await;
    }
}

/// Run the SOCKS5 handshake on `client`: greeting → method selection →
/// request → connect → reply. Returns `Ok(Some(target))` with the
/// connected upstream stream once the success reply is sent;
/// `Ok(None)` when we replied a failure and closed cleanly; `Err(())`
/// on a malformed/early-closed client we just drop.
async fn handshake(client: &mut TcpStream) -> Result<Option<TcpStream>, ()> {
    // ── 1. Greeting: VER NMETHODS METHODS[NMETHODS] ──────────────────
    // Read the 2-byte header first to learn NMETHODS, then exactly that
    // many method bytes. Bounded: NMETHODS is a u8, so at most 255+2.
    let mut hdr = [0u8; 2];
    if client.recv_exact(&mut hdr).await.is_err() {
        return Err(()); // client closed before greeting
    }
    // Reject a non-SOCKS5 VER on the FIRST byte — before reading
    // NMETHODS more bytes. A garbage/HTTP client (e.g. "GET …", where
    // byte 1 reads as a large NMETHODS) would otherwise make us block
    // waiting for method bytes that never come, until the handshake
    // deadline. Bail immediately and close.
    if hdr[0] != socks5::VER {
        return Err(());
    }
    let nmethods = hdr[1] as usize;
    let mut greeting = [0u8; 2 + 255];
    greeting[0] = hdr[0];
    greeting[1] = hdr[1];
    if nmethods > 0 && client.recv_exact(&mut greeting[2..2 + nmethods]).await.is_err() {
        return Err(());
    }
    match socks5::parse_greeting(&greeting[..2 + nmethods]) {
        Ok(_method) => {}
        // Malformed greeting (e.g. NMETHODS=0). No reply byte makes
        // sense (we never agreed a version) — just close.
        Err(GreetingError::BadVersion) | Err(GreetingError::NoMethods) => return Err(()),
    }
    // Method selection reply: `05 00` — version 5, no-auth chosen.
    if client.send_bytes(&[socks5::VER, socks5::METHOD_NO_AUTH]).await.is_err() {
        return Err(());
    }

    // ── 2. Request: VER CMD RSV ATYP DST.ADDR DST.PORT ───────────────
    // The address part is variable-length (4 bytes IPv4, 16 IPv6, or
    // 1+N domain), so we read the fixed 4-byte prefix FIRST and let
    // ATYP tell us how much (if any) more to read. That way a
    // domain/IPv6 request is rejected with the correct reply code
    // immediately, instead of blocking on bytes for an IPv4 layout
    // that never arrive. We only ever read the address for the IPv4
    // case we actually support.
    let mut prefix = [0u8; 4];
    if client.recv_exact(&mut prefix).await.is_err() {
        return Err(()); // client closed before sending the request
    }
    // Validate VER/CMD/ATYP on the prefix alone. For IPv4 we then read
    // the 4 addr + 2 port bytes and re-parse the full 10-byte request;
    // for any other ATYP (or a bad CMD/VER) `parse_request` already has
    // a verdict from the prefix — no address bytes needed.
    let mut req = [0u8; 10];
    req[..4].copy_from_slice(&prefix);
    // Indexing a `[u8; 4]` at 0/1/3 is panic-free — the length is known
    // at compile time. Only when the prefix is a well-formed IPv4
    // CONNECT do we read the remaining 6 address+port bytes.
    let is_ipv4_connect = prefix[0] == socks5::VER
        && prefix[1] == socks5::CMD_CONNECT
        && prefix[3] == socks5::ATYP_IPV4;
    if is_ipv4_connect && client.recv_exact(&mut req[4..]).await.is_err() {
        return Err(()); // IPv4 request truncated mid-address
    }
    let target = match socks5::parse_request(&req) {
        Ok(t) => t,
        Err(e) => {
            // Reply the matching REP code, then close. `Malformed` has
            // no useful code but we still answer (general-failure)
            // before dropping, so a confused client sees a verdict.
            reply(client, socks5::connect_reply(e.rep())).await;
            log_reject(&e);
            return Ok(None);
        }
    };

    // ── 3. Dial the target (the CLIENT role) ─────────────────────────
    let ip = IpAddr::V4(Ipv4Addr {
        addr: u32::from_ne_bytes(target.ip),
    });
    let dialed = timeout_us(CONNECT_DEADLINE_US, tcp_connect(ip, target.port)).await;
    let upstream = match dialed {
        Some(Ok(s)) => s,
        // Map the connect failure to the closest SOCKS5 reply code.
        Some(Err(e)) => {
            use waitless::runtime::TcpConnectError as E;
            let rep = match e {
                E::Refused => socks5::rep::CONNECTION_REFUSED,
                E::NoRoute => socks5::rep::NETWORK_UNREACHABLE,
                E::HostUnreachable | E::TimedOut => socks5::rep::HOST_UNREACHABLE,
                E::Failed => socks5::rep::GENERAL_FAILURE,
            };
            reply(client, socks5::connect_reply(rep)).await;
            return Ok(None);
        }
        // Our own connect deadline fired — report host-unreachable.
        None => {
            reply(client, socks5::connect_reply(socks5::rep::HOST_UNREACHABLE)).await;
            return Ok(None);
        }
    };

    // ── 4. Success reply, then hand back the upstream for relaying ───
    // The success path DOES care whether the reply landed (no point
    // relaying to a client that vanished), so check this send directly.
    if client
        .send_bytes(&socks5::connect_reply(socks5::rep::SUCCEEDED))
        .await
        .is_err()
    {
        return Err(()); // client vanished between connect and reply
    }
    log_connect(&target);
    Ok(Some(upstream))
}

// ---- Bidirectional relay ----------------------------------------------------

/// Relay bytes both ways between `client` and `target` until one side
/// closes — **zero-copy**: each inbound chunk is the transport's own
/// buffer (on bare metal, the NIC RX buffer the bytes DMA'd into),
/// lifted to an owned `IOBuf` (`into_owned` — no memcpy when the
/// buffer is already owned, which is the bare-metal case) and handed
/// to the other stream's `send`, which packs it straight into TCP
/// segments. The relay itself never copies a payload byte and owns no
/// buffers — a hundred thousand parked relays hold no per-flow copy
/// buffers at all (the old `recv`-into-`[u8; 16K]` version held two
/// per flow).
///
/// APPROACH: a single `select`-loop over the two directions' reads,
/// NOT a task per direction. Why: `TcpStream` is a `!Send`,
/// non-cloneable handle whose `recv_chunk`/`send` both take
/// `&mut self`. Two tasks (client→target, target→client) would each
/// need `&mut` to both streams, forcing `Rc<RefCell<TcpStream>>`
/// shared between them — and because a read holds its `&mut self`
/// borrow across the await, the two tasks would hold overlapping
/// `RefMut`s on the same stream and hit a `BorrowMutError` panic. A
/// SOCKS client is untrusted; a relay that can be panicked by
/// ordinary traffic is not acceptable. The select-loop owns both
/// streams as plain locals and only ever has one borrow live per
/// stream, so it is panic-free by construction.
///
/// Cancellation safety: each loop iteration `select`s a fresh
/// `client.recv_chunk()` against a fresh `target.recv_chunk()`. When
/// one resolves, `select` DROPS the other's future. `RecvChunk::drop`
/// clears the waker it parked on the connection (the repo's
/// Drop-clears-waker work), so the dropped read leaves no dangling
/// registration and the NEXT iteration re-arms cleanly. No bytes are
/// lost: an unresolved `recv_chunk` has, by definition, consumed no
/// chunk yet.
///
/// Concurrency story: both reads park on I/O; this task yields, and
/// the per-core loop services other connections meanwhile. It wakes
/// only when one direction has data (or the idle timer fires).
async fn relay(client: &mut TcpStream, target: &mut TcpStream) {
    loop {
        // Park on BOTH reads at once. The idle timer bounds a flow where
        // neither side ever speaks again (half-broken peers). Any byte
        // in either direction is progress and re-enters the loop, so a
        // long but live transfer never trips it.
        let ready = timeout_us(
            RELAY_IDLE_US,
            select(client.recv_chunk(), target.recv_chunk()),
        )
        .await;

        match ready {
            // client → target
            Some(Either::Left(Some(chunk))) => {
                // Zero-copy lift: the guard's buffer becomes an owned
                // IOBuf; `send` walks the chain into MSS-sized segments.
                let mut chain = IOBufChain::from(chunk.into_owned());
                if target.send(&mut chain).await.is_err() {
                    return; // target gone — tear down
                }
            }
            // target → client
            Some(Either::Right(Some(chunk))) => {
                let mut chain = IOBufChain::from(chunk.into_owned());
                if client.send(&mut chain).await.is_err() {
                    return; // client gone — tear down
                }
            }
            // EOF on either side. A fuller proxy could half-close and
            // keep draining the other direction; we close both —
            // simplest correct behaviour, and what CONNECT clients
            // expect for an IP tunnel.
            Some(Either::Left(None)) | Some(Either::Right(None)) => return,
            // Idle deadline: neither side moved for RELAY_IDLE_US. Reap.
            None => return,
        }
    }
}

// ---- Small helpers ----------------------------------------------------------

/// Send a fixed SOCKS5 failure reply, swallowing the error: every
/// caller is about to drop the connection regardless of whether the
/// last reply byte made it out. (The SUCCESS reply is sent inline in
/// `handshake` because that path DOES care — it won't relay to a
/// client that already left.)
async fn reply(client: &mut TcpStream, bytes: [u8; 10]) {
    let _ = client.send_bytes(&bytes).await;
}

/// One-line trace per successful CONNECT. Cheap, and the only thing a
/// proxy operator wants to see at a glance. (No client identity is
/// logged — this is an example, not an audit log.)
fn log_connect(t: &Target) {
    let [a, b, c, d] = t.ip;
    waitless::println!("connect {}.{}.{}.{}:{}", a, b, c, d, t.port);
}

/// One-line trace for a rejected request, naming why.
fn log_reject(e: &RequestError) {
    let why = match e {
        RequestError::Malformed => "malformed",
        RequestError::CommandNotSupported => "command-not-supported (only CONNECT)",
        RequestError::AddressTypeNotSupported => "address-type-not-supported (only IPv4 literal)",
    };
    waitless::println!("reject {}", why);
}
