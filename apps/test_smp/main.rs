// apps/test_smp — SMP boot test application.
//
// Simply starts the unikernel and exits. The SMP boot happens
// automatically during kernel init (before uni_main). The test
// script checks serial output for "N/N cores online".

#![no_std]

extern crate uni;

#[uni::main]
fn main() {
    uni::log(b"SMP test complete. Shutting down.\n");
}
