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
extern crate uni_http;
// Pull the virtio-net driver crate into the link closure for its
// `register_ethernet_driver!` link-section entry. Without this
// declaration, rustc drops the rlib (nothing else in the binary
// references it) and `linked_ethernet_drivers()` is empty at
// runtime. `os = "none"` gate matches the BUILD `select`: on native
// the crate isn't in the dep graph (POSIX sockets replace NIC).
#[cfg(target_os = "none")]
extern crate uni_driver_virtio_net;

use uni::net::{Net, NetBringUp};
use uni_http::{Request, Response, Server};

/// The app: holds the HTTP server for the program's lifetime.
struct HelloApp {
    _server: alloc::boxed::Box<Server>,
    _net: Net,
}

impl uni::App for HelloApp {}

impl HelloApp {
    fn new() -> Self {
        // Bring up networking explicitly (Phase 3 API). `enable`
        // runs DHCP and on failure applies the 10.0.2.15/24
        // fallback so the stack is always usable from here on.
        // We unwrap: the fallback makes a transient error case
        // invisible, so any Err surfaces a real misconfiguration
        // (e.g., NIC driver missing) we'd want to see.
        let net = Net::enable(NetBringUp::Dhcp)
            .expect("Net::enable failed — NIC driver missing?");

        let mut server = Server::new_boxed();
        server.default_handler(hello);
        server.listen(uni::config_port(80));
        HelloApp { _server: server, _net: net }
    }
}

fn hello(_: &Request) -> Response {
    Response::ok(b"text/plain", b"Hello from bare metal!\n")
}

#[uni::boot]
fn boot() {
    uni::run(HelloApp::new());
}
