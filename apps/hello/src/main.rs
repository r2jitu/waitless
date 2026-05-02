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

fn hello(_: &Request) -> Response {
    Response::ok(b"text/plain", b"Hello from bare metal!\n")
}

#[uni::boot]
async fn boot() {
    let net = Net::dhcp_or_static(
        uni::net::Ipv4Addr::new(10, 0, 2, 15),
        uni::net::Ipv4Addr::new(10, 0, 2, 2),
        uni::net::Ipv4Addr::new(255, 255, 255, 0),
    )
    .await
    .expect("Net bring-up failed");

    let mut handles = uni::Handles::new();
    handles.keep(net);
    handles.keep_or_log("http", uni_http::listen(80, hello));
    uni::run(handles);
}
