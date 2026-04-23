// apps/test_async — Async-runtime smoke test.
//
// Exercises the task arena, Waker wiring, and `Sleep` future. Also
// does a bind/drop roundtrip on `UdpSocket` to verify the reactor's
// registry + (on native) the backend bind hook wire up without
// needing external UDP traffic — `apps/webserver`'s `test_udp_echo`
// covers the full receive path.

#![no_std]

extern crate uni;

#[uni::boot]
fn boot() {
    uni::log(b"test_async: boot\n");

    let spawn_result = uni::runtime::spawn(async {
        uni::log(b"test_async: task started\n");
        uni::runtime::sleep_us(50_000).await;
        uni::log(b"test_async: task woke up\n");

        match uni::runtime::UdpSocket::bind(17) {
            Ok(sock) => {
                uni::log(b"test_async: udp bind ok\n");
                drop(sock);
                uni::log(b"test_async: udp drop ok\n");
            }
            Err(_) => uni::log(b"test_async: udp bind FAILED\n"),
        }

        let nested = uni::runtime::spawn(async {
            uni::runtime::sleep_us(10_000).await;
            uni::log(b"test_async: nested task done\n");
            uni::request_shutdown();
        });
        match nested {
            Ok(()) => uni::log(b"test_async: nested spawn ok\n"),
            Err(()) => {
                uni::log(b"test_async: nested spawn FAILED\n");
                uni::request_shutdown();
            }
        }
    });

    match spawn_result {
        Ok(()) => uni::log(b"test_async: spawn ok\n"),
        Err(()) => {
            uni::log(b"test_async: spawn FAILED\n");
            uni::request_shutdown();
        }
    }

    // Release the event loop / worker pool so tasks start being polled.
    uni::set_ready();
}
