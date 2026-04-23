// bazel/rules/native_main.rs — Root crate for native rust_binary.
//
// Native builds link libstd — which provides the panic handler,
// global allocator, and eh_personality — so this root crate stays
// minimal. It exists only to (a) pull in the app crate so its
// `uni_main` symbol is available at link time, and (b) hand off
// control to `uni::native_run()` (which drives the host POSIX
// event loop via the `uni_backend` crate).
//
// `uni` (and every crate under it other than `uni_backend`) stays
// `#![no_std]` — libraries compile as no_std rlibs and get linked
// into this std binary just fine. rustc's "unwinding panics are
// not supported without std" only fires for binary / staticlib
// crates, not rlibs, so the `bazel test` verb's `-Cpanic=unwind`
// works without the previous `_native_transition` + `tags =
// ["manual"]` dance.

// Force the app library to be linked (it provides uni_main).
// The app crate name is set by unikernel_binary() via --extern.
extern crate app;

fn main() {
    std::process::exit(uni::native_run());
}
