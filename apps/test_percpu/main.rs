// apps/test_percpu — Per-core state integration test.
//
// Verifies each core has independent per-core state:
//   - Unique core ID (cpu_id matches percpu slot)
//   - RX inbox push/pop works per-core
//   - TX staging push/pop works per-core
//
// Core 0 pushes test data to each AP's inbox, APs process and
// set atomic result flags. Core 0 polls results and prints.

#![no_std]

extern crate uni;
extern crate kernel;

use core::sync::atomic::{AtomicU8, Ordering};

const MAX_CORES: usize = 8;

// Per-core test results: 0 = pending, 1 = pass, 2 = fail
static RESULTS: [AtomicU8; MAX_CORES] = [const { AtomicU8::new(0) }; MAX_CORES];

fn test_poll(core_id: u32) -> bool {
    unsafe {
        let core = kernel::percpu::get(core_id);

        // Verify core ID matches
        if core.id != core_id {
            RESULTS[core_id as usize].store(2, Ordering::Release);
            return true;
        }

        // Pop the test frame that core 0 pushed to our inbox
        let frame = match core.rx_inbox.pop() {
            Some(f) => f,
            None => return false, // no work yet
        };

        // Verify the frame contains our core ID as a marker
        if frame.len() < 1 || frame[0] != core_id as u8 {
            RESULTS[core_id as usize].store(2, Ordering::Release);
            return true;
        }

        // Push a response to TX staging
        let response = [core_id as u8, 0xAA];
        core.tx_staging.push(&response);

        // Mark pass
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

    // Register AP poll function
    kernel::percpu::set_ap_poll_fn(test_poll);

    // Test core 0's own per-core state
    unsafe {
        let core0 = kernel::percpu::get(0);
        if core0.id != 0 {
            uni::log(b"Core 0: FAIL id mismatch\n");
        } else {
            core0.rx_inbox.push(&[42u8]);
            if let Some(data) = core0.rx_inbox.pop() {
                if data[0] == 42 {
                    uni::log(b"Core 0: inbox OK, id OK\n");
                } else {
                    uni::log(b"Core 0: FAIL inbox data\n");
                }
            } else {
                uni::log(b"Core 0: FAIL inbox empty\n");
            }
        }
    }

    // Push test data to each AP's inbox
    for i in 1..num_cores {
        unsafe {
            let core = kernel::percpu::get(i);
            let marker = [i as u8];
            core.rx_inbox.push(&marker);
        }
    }

    // Send IPI to wake APs
    for i in 1..num_cores {
        kernel::send_ipi(i);
    }

    // Wait for all APs to complete, polling results
    let expected = num_cores - 1;
    let mut done = 0u32;
    for _ in 0..50_000_000u32 {
        done = 0;
        for i in 1..num_cores {
            if RESULTS[i as usize].load(Ordering::Acquire) != 0 {
                done += 1;
            }
        }
        if done >= expected { break; }
    }

    // Print results for each AP (core 0 does all printing — no garbled output)
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
}
