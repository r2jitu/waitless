// uni/macros/lib.rs — Proc macro for #[uni::main]
//
// Transforms a plain `fn main() -> i32` into the platform-specific
// entry point:
//
//   Unikernel: #[no_mangle] pub extern "C" fn uni_main() -> i32
//   Native:    #[no_mangle] pub extern "C" fn uni_main() -> i32
//
// Both platforms resolve uni_main at link time — the unikernel's
// kernel/entry.rs calls it after boot, and the native binary's
// native_main.rs calls it after init.

extern crate proc_macro;
use proc_macro::TokenStream;

/// Marks a function as the unikernel application entry point.
///
/// # Example
/// ```ignore
/// #[uni::main]
/// fn main() -> i32 {
///     // application code
///     0
/// }
/// ```
///
/// Expands to a `#[no_mangle] pub extern "C" fn uni_main()` that the
/// platform runtime calls after initialization.
#[proc_macro_attribute]
pub fn main(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let source = item.to_string();

    // Extract the function body (everything between the first { and last })
    let body_start = match source.find('{') {
        Some(i) => i,
        None => return item,
    };
    let body = &source[body_start..];

    // Generate the entry point
    let output = format!(
        r#"
#[unsafe(no_mangle)]
pub extern "C" fn uni_main() -> i32 {body}
"#,
        body = body,
    );

    output.parse().unwrap()
}
