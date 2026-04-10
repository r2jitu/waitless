// tools/hvf-runner/src/lib.rs
//
// Library surface for the hvf-runner crate. The binary (src/main.rs)
// uses these modules directly via `mod` declarations; this lib.rs
// re-exports them so the Phase 0 smoke test (examples/smoke.rs) can
// also reach the FFI bindings.

pub mod hvf;
