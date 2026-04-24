// uni/macros/lib.rs — Proc macro for `#[uni::boot]`.
//
// The platform entry point is a C-ABI symbol named `uni_main`. The
// macro keeps the user's `fn boot()` / `async fn boot()` intact (so
// the IDE lints its body correctly), then emits a `uni_main` wrapper
// that spawns the boot future on the core-0 task arena.
//
// Running boot as a task means the event loop is already ticking
// while boot code runs — `Net::enable(Dhcp).await` yields between
// DISCOVER/REQUEST and OFFER/ACK, the `net_flush_cb` hook kicks the
// virtio TX ring between polls, and the pre-eventloop DHCP phase
// (with its deferred-kick workaround) goes away entirely.

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
pub extern "C" fn uni_main() {{
    let _ = {spawn_expr};
}}
"#,
        user_fn = source,
        spawn_expr = spawn_expr,
    );

    output.parse().unwrap()
}
