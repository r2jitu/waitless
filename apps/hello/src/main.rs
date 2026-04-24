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

/// Holds the `Server` (for graceful shutdown) and `Net` (keeps
/// the network stack alive) for the program's lifetime. Dropping
/// the app drops the Server, which aborts the accept loop and
/// signals per-conn tasks to exit.
struct HelloApp {
    _server: Server,
    _net: Net,
}

impl uni::App for HelloApp {}

impl HelloApp {
    fn new(net: Net) -> Self {
        let mut server = Server::builder()
            .default_handler(hello)
            .build();
        server
            .listen(uni::config_port(80))
            .expect("HelloApp: TCP listener bind failed");
        HelloApp { _server: server, _net: net }
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
