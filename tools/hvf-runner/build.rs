// tools/hvf-runner/build.rs
//
// Two jobs:
//   1. Emit the link flags that pull in Apple Hypervisor.framework
//      (Bazel does this itself via rustc_flags; this file is only read
//      by plain `cargo build`).
//   2. Assemble the Phase 0 smoke test stubs from examples/stubs.s into
//      raw binary files that examples/smoke.rs can include_bytes!.
//
// The assembler step runs every `cargo build` regardless of target
// because the example binary that consumes the output only compiles on
// macOS arm64 anyway — `cargo check` on other hosts is not a supported
// workflow for this crate.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // --- Part 1: link flags (plain cargo build only) ---
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("apple-darwin") {
        panic!(
            "hvf-runner only supports Apple platforms (target = {target:?}); \
             Apple Hypervisor.framework is macOS-only."
        );
    }
    println!("cargo:rustc-link-lib=framework=Hypervisor");
    println!("cargo:rustc-link-lib=framework=Foundation");

    // --- Part 2: assemble Phase 0 smoke-test stubs ---
    assemble_smoke_stubs();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=examples/stubs.s");
}

/// Assemble `examples/stubs.s` and extract each `.stub_*` section into a
/// separate raw binary file in $OUT_DIR. The Rust harness then uses
/// `include_bytes!(concat!(env!("OUT_DIR"), "/stub_*.bin"))`.
///
/// We shell out to `clang` (to assemble) and `llvm-objcopy` (to extract).
/// Both ship with macOS Command Line Tools / Homebrew.
fn assemble_smoke_stubs() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest_dir.join("examples").join("stubs.s");
    let obj = out_dir.join("stubs.o");

    // Use clang with --target=aarch64-unknown-none so the assembler
    // doesn't pull in macOS Mach-O object file conventions (PIE,
    // __TEXT/__DATA segment names etc.); we want a plain ELF so we can
    // pull out sections by name via llvm-objcopy.
    // -march=armv8.2-a enables LSE (large-system extension) atomics
    // like CASALB, which the smoke test uses to verify that LSE atomics
    // work against guest RAM under HVF. Apple Silicon implements LSE
    // natively; the kernel uses it too. armv8.2-a is the lowest floor
    // that includes LSE as a mandatory feature.
    let status = Command::new("clang")
        .args([
            "--target=aarch64-unknown-none",
            "-march=armv8.2-a",
            "-nostdlib",
            "-c",
            "-o",
        ])
        .arg(&obj)
        .arg(&src)
        .status()
        .expect("failed to invoke clang (is Xcode Command Line Tools installed?)");
    assert!(status.success(), "clang failed to assemble examples/stubs.s");

    // Locate llvm-objcopy. Homebrew and Command Line Tools put it in
    // different places; try the usual suspects.
    let objcopy = locate_llvm_objcopy();

    for (section, filename) in &[
        (".stub_atomics", "stub_atomics.bin"),
        (".stub_instr", "stub_instr.bin"),
        (".stub_gic_spi", "stub_gic_spi.bin"),
        (".stub_mmu_self", "stub_mmu_self.bin"),
    ] {
        let out_file = out_dir.join(filename);
        let status = Command::new(&objcopy)
            .args([
                "-O",
                "binary",
                "--only-section",
                section,
            ])
            .arg(&obj)
            .arg(&out_file)
            .status()
            .expect("failed to invoke llvm-objcopy");
        assert!(
            status.success(),
            "llvm-objcopy failed to extract section {section}"
        );
        // Sanity check that the section isn't empty.
        let meta = std::fs::metadata(&out_file).expect("stat extracted section");
        assert!(
            meta.len() > 0,
            "section {section} extracted to an empty file — \
             is the section name correct in examples/stubs.s?"
        );
    }
}

/// Find llvm-objcopy on the host. Prefer Homebrew's LLVM because it's
/// the version most likely to support Mach-O and ELF interchangeably
/// and is maintained more recently than the CLT bundled LLVM.
fn locate_llvm_objcopy() -> PathBuf {
    let candidates = [
        "/opt/homebrew/opt/llvm/bin/llvm-objcopy",
        "/usr/local/opt/llvm/bin/llvm-objcopy",
        "/Library/Developer/CommandLineTools/usr/bin/llvm-objcopy",
        "/usr/bin/llvm-objcopy",
    ];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return PathBuf::from(c);
        }
    }
    // Fall back to PATH lookup.
    PathBuf::from("llvm-objcopy")
}
