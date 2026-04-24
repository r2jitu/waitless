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

use uni::net::{Net, NetBringUp};
use uni_http::{Request, Response, Server};

/// The app holds the `Net` so the network stack stays up for the
/// process lifetime. The HTTP server itself is `Box::leak`-ed
/// before `listen()` — accept tasks capture `&'static Server`.
struct HelloApp {
    _net: Net,
}

impl uni::App for HelloApp {}

impl HelloApp {
    fn new(net: Net) -> Self {
        let mut server = Server::new_boxed();
        server.default_handler(hello);
        let server: &'static Server = alloc::boxed::Box::leak(server);
        server.listen(uni::config_port(80)).leak();
        HelloApp { _net: net }
    }
}

fn hello(_: &Request) -> Response {
    Response::ok(b"text/plain", b"Hello from bare metal!\n")
}

#[uni::boot]
async fn boot() {
    let net = Net::enable(NetBringUp::Dhcp)
        .await
        .expect("Net::enable failed — NIC driver missing?");
    uni::run(HelloApp::new(net));
}
