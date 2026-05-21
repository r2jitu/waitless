// UniKernel Example: Minimal HTTP Hello World
//
// The smallest useful unikernel app: bring up the network, listen
// on :80, return one plain-text response per request. For a richer
// example with TLS / UDP / gateway / diagnostics see
// apps/webserver/.

#![no_std]

extern crate alloc;

use http::{Request, Response};
use waitless::net::Net;

async fn hello(_: &Request, _: &mut http::BodyReader<'_, waitless::runtime::TcpStream>) -> Response {
    Response::ok(b"text/plain", b"Hello from bare metal!\n")
}

#[waitless::init]
async fn init() {
    Net::up().await.expect("Net::up failed");
    http::listen(80, hello).expect("http bind");
}
