// UniKernel Example: Minimal HTTP Hello World
//
// The smallest useful unikernel app. Defines a single handler
// that returns a plain-text response; shows the full framework
// shape (struct → impl uni::App → #[uni::boot] fn boot) without
// any diagnostics, TLS, or multi-port machinery. For a richer
// example see apps/webserver/.

#![no_std]

extern crate alloc;
extern crate uni;
extern crate uni_http;

use uni::net::{Net, NetBringUp};
use uni_http::{Request, Response};

/// Holds the listener `TcpHandle` (drop tears down the accept
/// task + releases the port) and `Net` (keeps the network stack
/// alive) for the program's lifetime.
struct HelloApp {
    _http: uni::runtime::TcpHandle,
    _net: Net,
}

impl uni::App for HelloApp {}

impl HelloApp {
    fn new(net: Net) -> Self {
        let http = uni_http::listen(uni::config_port(80), hello)
            .expect("HelloApp: bind failed");
        HelloApp { _http: http, _net: net }
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
