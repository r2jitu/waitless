// UniKernel Example: Minimal HTTP Hello World
//
// The smallest useful unikernel app: bring up the network, listen
// on :80, return one plain-text response per request. For a richer
// example with TLS / UDP / gateway / diagnostics see
// apps/webserver/.

#![no_std]

extern crate alloc;

use uni::net::Net;
use uni_http::{Request, Response};

async fn hello(_: &Request) -> Response {
    Response::ok(b"text/plain", b"Hello from bare metal!\n")
}

#[uni::init]
async fn init() {
    Net::up().await.expect("Net::up failed");
    uni_http::listen(80, hello).expect("http bind");
}
