// UniKernel Example: Minimal HTTP Hello World
//
// The smallest useful unikernel app. Defines a single route that
// returns a plain-text response; shows the full framework shape
// (struct → impl uni::App → #[uni::boot] fn boot) without any
// diagnostics, TLS, or multi-route machinery. For a richer
// example see apps/webserver/.

#![no_std]

extern crate alloc;
extern crate uni;

use uni::http::{Request, Response, Server};

/// The app: holds the HTTP server for the program's lifetime.
struct HelloApp {
    _server: alloc::boxed::Box<Server>,
}

impl uni::App for HelloApp {}

impl HelloApp {
    fn new() -> Self {
        let mut server = Server::new_boxed();
        server.default_handler(hello);
        server.listen(uni::config_port(80));
        HelloApp { _server: server }
    }
}

fn hello(_: &Request) -> Response {
    Response::ok(b"text/plain", b"Hello from bare metal!\n")
}

#[uni::boot]
fn boot() {
    uni::run(HelloApp::new());
}
