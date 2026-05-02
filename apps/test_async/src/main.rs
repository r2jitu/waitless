// apps/test_async — Async-runtime smoke test.
//
// Exercises the task arena, Waker wiring, and `Sleep` future.
// Also verifies socket-lifecycle cleanup end-to-end: bind+drop
// and bind+run+drop both re-release their port so the next
// `bind(same_port)` succeeds. That's a real regression catch for
// the UdpSocket/TcpListener `Drop` impls and for `UdpHandle`/
// `TcpHandle::drop` task-abort + port-release ordering.

#![no_std]

extern crate uni;

#[uni::boot]
fn boot() {
    uni::log(b"test_async: boot\n");

    let spawn_result = uni::runtime::spawn(async {
        uni::log(b"test_async: task started\n");
        uni::runtime::sleep_us(50_000).await;
        uni::log(b"test_async: task woke up\n");

        // ── Socket cleanup coverage ──────────────────────────
        // Each phase binds the SAME port twice: if Drop failed
        // to release the slot the second bind would fail with
        // PortInUse. Fresh port per phase so phases are
        // independent.
        run_udp_bind_drop_cycle();
        run_udp_fanout_drop_cycle();
        run_tcp_bind_drop_cycle();
        run_tcp_fanout_drop_cycle();

        let nested = uni::runtime::spawn(async {
            uni::runtime::sleep_us(10_000).await;
            uni::log(b"test_async: nested task done\n");
            uni::request_shutdown();
        });
        match nested {
            Ok(_handle) => uni::log(b"test_async: nested spawn ok\n"),
            Err(()) => {
                uni::log(b"test_async: nested spawn FAILED\n");
                uni::request_shutdown();
            }
        }
    });

    match spawn_result {
        Ok(_handle) => uni::log(b"test_async: spawn ok\n"),
        Err(()) => {
            uni::log(b"test_async: spawn FAILED\n");
            uni::request_shutdown();
        }
    }

    // Release the event loop / worker pool so tasks start being polled.
    uni::set_ready();
}

/// Phase 1: `UdpSocket::bind` + `drop` + re-bind same port.
/// Verifies `UdpSocket::Drop` releases the port-registry slot.
fn run_udp_bind_drop_cycle() {
    // All test ports use the 17000 range: unprivileged on POSIX
    // (the `native` variant runs as a plain user binary so
    // anything < 1024 would EACCES) and unused by the webserver
    // tests that may run in parallel.
    const PORT: u16 = 17017;
    match uni::runtime::UdpSocket::bind(PORT) {
        Ok(sock) => {
            uni::log(b"test_async: udp bind ok\n");
            drop(sock);
            uni::log(b"test_async: udp drop ok\n");
        }
        Err(_) => {
            uni::log(b"test_async: udp bind FAILED\n");
            return;
        }
    }
    match uni::runtime::UdpSocket::bind(PORT) {
        Ok(_sock) => uni::log(b"test_async: udp rebind ok\n"),
        Err(_) => uni::log(b"test_async: udp rebind FAILED\n"),
    }
    // The second `_sock` drops at end of scope — keeps the port
    // clean for the next phase if we ever reuse PORT.
}

/// Phase 2: bind + `run` + drop handle + re-bind. Verifies
/// `UdpHandle::Drop` aborts per-worker recv tasks AND releases
/// the port (not one or the other).
fn run_udp_fanout_drop_cycle() {
    const PORT: u16 = 17019;
    match uni::runtime::UdpSocket::bind(PORT) {
        Ok(sock) => {
            // Body never receives in this test (nothing is sending
            // to PORT) but the per-worker recv tasks get spawned
            // and parked — exactly what `drop` needs to tear down.
            let handle = sock.run(|sock| async move {
                let mut buf = [0u8; 1500];
                loop {
                    let _ = sock.recv_from(&mut buf).await;
                }
            });
            drop(handle);
            uni::log(b"test_async: udp fanout drop ok\n");
        }
        Err(_) => {
            uni::log(b"test_async: udp fanout bind FAILED\n");
            return;
        }
    }
    match uni::runtime::UdpSocket::bind(PORT) {
        Ok(_sock) => uni::log(b"test_async: udp fanout rebind ok\n"),
        Err(_) => uni::log(b"test_async: udp fanout rebind FAILED\n"),
    }
}

/// Phase 3: `TcpListener::bind` + drop + re-bind. Verifies
/// `TcpListener::Drop` releases the port slot.
fn run_tcp_bind_drop_cycle() {
    const PORT: u16 = 17021;
    match uni::runtime::TcpListener::bind(PORT) {
        Ok(listener) => {
            uni::log(b"test_async: tcp bind ok\n");
            drop(listener);
            uni::log(b"test_async: tcp drop ok\n");
        }
        Err(_) => {
            uni::log(b"test_async: tcp bind FAILED\n");
            return;
        }
    }
    match uni::runtime::TcpListener::bind(PORT) {
        Ok(_listener) => uni::log(b"test_async: tcp rebind ok\n"),
        Err(_) => uni::log(b"test_async: tcp rebind FAILED\n"),
    }
}

/// Phase 4: TCP `run(body)` + drop handle + re-bind. Mirrors the
/// UDP fanout test on the accept side.
fn run_tcp_fanout_drop_cycle() {
    const PORT: u16 = 17023;
    match uni::runtime::TcpListener::bind(PORT) {
        Ok(listener) => {
            // Accept-loop body is never invoked here — no client
            // connects to port 23 during this test. The per-
            // worker accept tasks get spawned + parked, which is
            // what we want Drop to clean up.
            let handle = listener.run(|_stream| async {});
            drop(handle);
            uni::log(b"test_async: tcp fanout drop ok\n");
        }
        Err(_) => {
            uni::log(b"test_async: tcp fanout bind FAILED\n");
            return;
        }
    }
    match uni::runtime::TcpListener::bind(PORT) {
        Ok(_listener) => uni::log(b"test_async: tcp fanout rebind ok\n"),
        Err(_) => uni::log(b"test_async: tcp fanout rebind FAILED\n"),
    }
}
