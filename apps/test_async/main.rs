// apps/test_async — Async-runtime smoke test.
//
// Spawns a future that logs, sleeps on a timer, logs again, then
// requests shutdown. Exercises `kernel::executor::spawn`, the
// per-core task arena, the RawWakerVTable, the Sleep future, and
// the timer-wheel integration in `kernel::eventloop`.

#![no_std]

extern crate kernel;
extern crate uni;

#[uni::boot]
fn boot() {
    uni::log(b"test_async: boot\n");

    let spawn_result = kernel::executor::spawn(async {
        uni::log(b"test_async: task started\n");
        kernel::executor::sleep_us(50_000).await;
        uni::log(b"test_async: task woke up\n");

        let nested = kernel::executor::spawn(async {
            kernel::executor::sleep_us(10_000).await;
            uni::log(b"test_async: nested task done\n");
            kernel::eventloop::request_shutdown();
        });
        match nested {
            Ok(()) => uni::log(b"test_async: nested spawn ok\n"),
            Err(()) => {
                uni::log(b"test_async: nested spawn FAILED\n");
                kernel::eventloop::request_shutdown();
            }
        }
    });

    match spawn_result {
        Ok(()) => uni::log(b"test_async: spawn ok\n"),
        Err(()) => {
            uni::log(b"test_async: spawn FAILED\n");
            kernel::eventloop::request_shutdown();
        }
    }

    // Release the event loop so every core starts polling.
    kernel::eventloop::set_ready();
}
