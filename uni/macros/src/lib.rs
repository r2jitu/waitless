// uni/macros/lib.rs — Proc macro for `#[uni::boot]`.
//
// The platform entry point is a Rust-ABI symbol named `uni_boot`
// with `#[no_mangle]` so boot/entry.rs (bare-metal) and
// uni-backend/src/native/mod.rs can resolve it at link time. Since
// both sides are Rust and the function takes no args / returns
// nothing, there's no point pretending this is an FFI boundary —
// `extern "C"` is unnecessary ceremony.
//
// The macro keeps the user's `fn boot()` / `async fn boot()`
// intact (so the IDE lints its body correctly), then emits a
// `uni_boot` wrapper that spawns the boot future on the core-0
// task arena.
//
// Running boot as a task means the event loop is already ticking
// while boot code runs — `Net::enable(Dhcp).await` yields between
// DISCOVER/REQUEST and OFFER/ACK, the `net_flush_cb` hook kicks the
// virtio TX ring between polls, and the pre-eventloop DHCP phase
// (with its deferred-kick workaround) goes away entirely.
//
// Why the macro spawns (not the bare-metal / native entry points):
// there's exactly one `#[uni::boot]` per binary and it's the only
// place that has the user's async body in Rust scope. Handing a
// `Pin<Box<dyn Future>>` across the entry-point boundary would
// need either FFI-over-futures or a link-time registry for a
// single registrant — both more machinery than value. Entry points
// stay runtime-agnostic this way.

extern crate proc_macro;
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn boot(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let source = item.to_string();

    // Detect `async fn` vs `fn` so the spawn wrapper knows whether
    // `boot()` returns a future directly or is a sync function we
    // need to wrap in an `async { }` block.
    let is_async = source
        .split_whitespace()
        .take_while(|t| *t != "fn")
        .any(|t| t == "async");

    let spawn_expr = if is_async {
        "::uni::runtime::spawn(boot())"
    } else {
        "::uni::runtime::spawn(async move { boot() })"
    };

    let output = format!(
        r#"
{user_fn}

#[unsafe(no_mangle)]
pub fn uni_boot() {{
    let _ = {spawn_expr};
}}
"#,
        user_fn = source,
        spawn_expr = spawn_expr,
    );

    output.parse().unwrap()
}
