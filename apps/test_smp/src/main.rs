// apps/test_smp — SMP boot + IPI test application.
//
// Tests: multi-core boot, inter-processor interrupt delivery.

#![no_std]

extern crate uni;
extern crate uni_kernel;

#[uni::init]
fn init() {
    // Wait until every configured core has come up. The kernel's
    // `start_secondary_cores` no longer waits BSP-side, so we
    // explicitly synchronise here before the IPI test (which
    // requires core 1 to be online to receive the SGI) and before
    // the final marker (so the per-AP `[SMP] core N online` lines
    // are guaranteed to be in the serial log when the test driver
    // captures it).
    if !uni_kernel::wait_for_cores_online(2_000_000) {
        uni::log(b"SMP test: not all cores came up within 2 s\n");
    }

    uni::log(b"SMP test: cores booted.\n");

    // Test IPI: core 0 sends SGI to core 1, check that it was received
    #[cfg(target_arch = "aarch64")]
    {
        let before = uni_kernel::aarch64::smp::ipi_count();
        uni_kernel::aarch64::smp::send_sgi_to(1);

        // Wall-clock wait (poll the IPI count up to 1 s). Old code
        // used `for _ in 0..100_000 { nop }`, which on QEMU TCG with
        // single-threaded scheduling never yielded to the target AP
        // — TCG runs one vCPU at a time and only switches at MMIO /
        // halt boundaries; once the BSP boot path stopped doing
        // serial-poll MMIO every byte, BSP raced through the whole
        // test in microseconds and the SGI sat undelivered until
        // long after `ipi_count()` was checked.
        let deadline = uni_kernel::time::now_cycles()
            .wrapping_add(1_000_000 * uni_kernel::time::cycles_per_us());
        while uni_kernel::aarch64::smp::ipi_count() == before
            && uni_kernel::time::now_cycles() < deadline
        {
            unsafe { core::arch::asm!("yield"); }
        }

        let after = uni_kernel::aarch64::smp::ipi_count();
        if after > before {
            uni::log(b"IPI test: PASS (SGI delivered to core 1)\n");
        } else {
            uni::log(b"IPI test: FAIL (SGI not received)\n");
        }
    }

    uni::log(b"SMP test complete. Shutting down.\n");
}
