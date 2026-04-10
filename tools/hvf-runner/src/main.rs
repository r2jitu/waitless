// tools/hvf-runner/src/main.rs
//
// Entry point. Placeholder for Phase 1 — the real runner orchestration
// (vm.rs, run loop, device dispatch) lands in later commits. For now this
// just prints a message so the binary target exists and the Bazel/cargo
// build graph has something to produce.
//
// Phase 0 smoke tests run through `cargo run --example smoke`, not this
// binary.

fn main() {
    eprintln!(
        "run-hvf: not yet implemented. Run `cargo run --example smoke` \
         for the Phase 0 smoke tests."
    );
    std::process::exit(2);
}
