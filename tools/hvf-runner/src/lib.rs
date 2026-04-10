// tools/hvf-runner/src/lib.rs
//
// Library surface for the hvf-runner crate. Kept deliberately small so
// that the binary (src/main.rs) and the Phase 0 smoke test
// (examples/smoke.rs) can share one set of FFI bindings and a single
// HvError type.
//
// Everything else (run loop, device emulation, NetBridge, FDT writer) is
// added incrementally in subsequent phases. The crate compiles at every
// phase boundary so work can pause mid-plan and the binary still builds.

pub mod hvf;
