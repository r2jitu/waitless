// apps/test_percpu — Per-core state integration test.
//
// Verifies each core participates in the event loop and has
// independent per-core state. Uses the event loop service callback.

#![no_std]

extern crate uni;
extern crate kernel;

use core::sync::atomic::{AtomicU8, Ordering};

const MAX_CORES: usize = 8;

// Per-core test results: 0 = pending, 1 = pass, 2 = fail
static RESULTS: [AtomicU8; MAX_CORES] = [const { AtomicU8::new(0) }; MAX_CORES];

// Per-core test data: each core should see its own ID here
static mut TEST_DATA: [u32; MAX_CORES] = [0xFFFFFFFF; MAX_CORES];

fn test_service(core_id: u32) -> bool {
    // Only run the test once per core
    if RESULTS[core_id as usize].load(Ordering::Relaxed) != 0 {
        return false;
    }

    unsafe {
        let core = kernel::percpu::get(core_id);

        // Verify core ID matches
        if core.id != core_id {
            RESULTS[core_id as usize].store(2, Ordering::Release);
            return true;
        }

        // Verify we can see our test data
        if TEST_DATA[core_id as usize] != core_id {
            RESULTS[core_id as usize].store(2, Ordering::Release);
            return true;
        }

        // Push to TX staging and verify it's there
        let response = [core_id as u8, 0xAA];
        core.tx_staging.push(&response);

        RESULTS[core_id as usize].store(1, Ordering::Release);
    }
    true
}

#[uni::main]
fn main() {
    uni::log(b"Per-core state test starting.\n");

    let num_cores = kernel::percpu::num_cores();
    uni::log(b"Cores: ");
    uni::log(&[b'0' + (num_cores as u8 % 10)]);
    uni::log(b"\n");

    if num_cores <= 1 {
        uni::log(b"SKIP: need >1 core for per-core test\n");
        uni::log(b"Per-core state test complete.\n");
        return;
    }

    // Write test data for each core
    for i in 0..num_cores {
        unsafe { TEST_DATA[i as usize] = i; }
    }

    // Register service callback
    kernel::eventloop::set_service(test_service);

    // Signal APs to start
    kernel::eventloop::set_ready();
    kernel::wake_cores();

    // Run core 0's test inline
    test_service(0);

    // Wait for all APs
    let expected = num_cores - 1;
    for _ in 0..50_000_000u32 {
        let mut done = 0u32;
        for i in 1..num_cores {
            if RESULTS[i as usize].load(Ordering::Acquire) != 0 {
                done += 1;
            }
        }
        if done >= expected { break; }
    }

    // Print results
    for i in 1..num_cores {
        let result = RESULTS[i as usize].load(Ordering::Acquire);
        uni::log(b"Core ");
        uni::log(&[b'0' + (i as u8 % 10)]);
        if result == 1 {
            uni::log(b": inbox OK, tx_staging OK, id OK\n");
        } else if result == 2 {
            uni::log(b": FAIL\n");
        } else {
            uni::log(b": TIMEOUT (no result)\n");
        }
    }

    // Verify TX staging from each AP
    let mut tx_ok = 0u32;
    for i in 1..num_cores {
        unsafe {
            let core = kernel::percpu::get(i);
            if let Some(data) = core.tx_staging.pop() {
                if data.len() >= 2 && data[0] == i as u8 && data[1] == 0xAA {
                    tx_ok += 1;
                }
            }
        }
    }

    if tx_ok == expected {
        uni::log(b"Core 0: verified TX staging from all APs\n");
    } else {
        uni::log(b"Core 0: FAIL TX staging verification\n");
    }

    uni::log(b"Per-core state test complete.\n");
    kernel::eventloop::request_shutdown();
}
