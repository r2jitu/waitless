// apps/test_smp — SMP boot + IPI test application.
//
// Tests: multi-core boot, inter-processor interrupt delivery.

#![no_std]

extern crate uni;

#[cfg(target_arch = "aarch64")]
extern crate uni_kernel;

#[uni::boot]
fn boot() {
    uni::log(b"SMP test: cores booted.\n");

    // Test IPI: core 0 sends SGI to core 1, check that it was received
    #[cfg(target_arch = "aarch64")]
    {
        let before = uni_kernel::aarch64::smp::ipi_count();
        uni_kernel::aarch64::smp::send_sgi_to(1);

        // Brief delay for IPI delivery
        for _ in 0..100_000 {
            unsafe { core::arch::asm!("nop"); }
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
