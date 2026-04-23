// uni/macros/lib.rs — Proc macro for `#[uni::boot]`.
//
// The unikernel's platform entry point is a C-ABI symbol named
// `uni_main` — the bare-metal boot code and native's `main` both
// resolve it at link time. Users write a regular Rust function and
// tag it with `#[uni::boot]`; the macro renames it to `uni_main`
// and gives it the required `extern "C"` / no-mangle attributes.
//
// The macro does no body transformation: it preserves the function
// body exactly, so the user's `fn boot()` behaves like any normal
// Rust function during execution.

extern crate proc_macro;
use proc_macro::TokenStream;

/// Marks a function as the unikernel entry point. The platform
/// runtime (`uni_kernel::entry` on bare metal, `native::main` on
/// POSIX) calls the resulting `uni_main` symbol after init.
///
/// The function is a normal Rust function; typical shape is:
///
/// ```ignore
/// #[uni::boot]
/// fn boot() {
///     uni::run(MyApp::new());
/// }
/// ```
///
/// For pure "run code and halt" programs (e.g. test binaries),
/// the body can just contain that code without calling `uni::run`.
#[proc_macro_attribute]
pub fn boot(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let source = item.to_string();

    // Extract the function body — everything from the first `{`.
    let body_start = match source.find('{') {
        Some(i) => i,
        None => return item,
    };
    let body = &source[body_start..];

    let output = format!(
        r#"
#[unsafe(no_mangle)]
pub extern "C" fn uni_main() {body}
"#,
        body = body,
    );

    output.parse().unwrap()
}
