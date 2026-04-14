// tools/hvf-runner/build.rs
//
// Emit the link flags that pull in Apple Hypervisor.framework. Bazel
// does this itself via rustc_flags; this file is only read by plain
// `cargo build`.

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("apple-darwin") {
        panic!(
            "hvf-runner only supports Apple platforms (target = {target:?}); \
             Apple Hypervisor.framework is macOS-only."
        );
    }
    println!("cargo:rustc-link-lib=framework=Hypervisor");
    println!("cargo:rustc-link-lib=framework=Foundation");

    println!("cargo:rerun-if-changed=build.rs");
}
