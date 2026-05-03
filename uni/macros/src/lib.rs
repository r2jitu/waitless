// uni/macros/lib.rs — Proc macro for `#[uni::init]`.
//
// The platform entry point is a Rust-ABI symbol named `uni_init`
// with `#[no_mangle]` so boot/entry.rs (bare-metal) and
// uni-backend/src/native/mod.rs can resolve it at link time. Since
// both sides are Rust and the function takes no args / returns
// nothing, there's no point pretending this is an FFI boundary —
// `extern "C"` is unnecessary ceremony.
//
// The macro keeps the user's `fn init()` / `async fn init()`
// intact (so the IDE lints its body correctly), then emits a
// `uni_init` wrapper that spawns the init future on core 0's
// task arena.
//
// Running init as a task means the event loop is already ticking
// while init code runs — `Net::enable(Dhcp).await` yields between
// DISCOVER/REQUEST and OFFER/ACK, the `net_flush_cb` hook kicks the
// virtio TX ring between polls, and the pre-eventloop DHCP phase
// (with its deferred-kick workaround) goes away entirely.
//
// Why the macro spawns (not the bare-metal / native entry points):
// there's exactly one `#[uni::init]` per binary and it's the only
// place that has the user's async body in Rust scope. Handing a
// `Pin<Box<dyn Future>>` across the entry-point boundary would
// need either FFI-over-futures or a link-time registry for a
// single registrant — both more machinery than value. Entry points
// stay runtime-agnostic this way.
//
// Naming: `init` rather than `boot` because the kernel does the
// boot — load image, set up MMU, start cores, init heap. What this
// macro wraps is the user's *init script* — runs after boot, sets
// up app state (network, config, listeners), then yields to the
// event loop. Same role as `/etc/init.d/` scripts or systemd unit
// `ExecStart=` directives in Linux.

extern crate proc_macro;
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn init(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let source = item.to_string();

    // Detect `async fn` vs `fn` so the spawn wrapper knows whether
    // `init()` returns a future directly or is a sync function we
    // need to wrap in an `async { }` block.
    let is_async = source
        .split_whitespace()
        .take_while(|t| *t != "fn")
        .any(|t| t == "async");

    // Wrap the user's body in an async block that installs the
    // shutdown hook + signals readiness as a final step. Listener
    // handles registered via `uni::tcp_listen` etc. live in the
    // runtime's leak slot; nothing else needs to happen on the
    // user's part once `init()` returns.
    let body_call = if is_async {
        "init().await"
    } else {
        "init()"
    };

    let output = format!(
        r#"
{user_fn}

#[unsafe(no_mangle)]
pub fn uni_init() {{
    let _ = ::uni::runtime::spawn(async move {{
        {body_call};
        ::uni::_install_shutdown_hook();
        ::uni::set_ready();
        ::uni::log(b"ready\n");
    }});
}}
"#,
        user_fn = source,
        body_call = body_call,
    );

    output.parse().unwrap()
}
