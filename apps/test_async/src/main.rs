// apps/test_async — Async-runtime smoke test.
//
// Spawns a future that logs, sleeps on a timer, logs again, then
// requests shutdown. Exercises `uni::runtime::spawn`, the backend
// task arena (kernel on unikernel / std on native), the waker wiring
// and the `Sleep` future end-to-end.

#![no_std]

extern crate uni;

#[uni::boot]
fn boot() {
    uni::log(b"test_async: boot\n");

    let spawn_result = uni::runtime::spawn(async {
        uni::log(b"test_async: task started\n");
        uni::runtime::sleep_us(50_000).await;
        uni::log(b"test_async: task woke up\n");

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
