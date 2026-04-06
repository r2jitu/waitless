// net/lib.rs — Network stack umbrella crate.
//
// Re-exports per-protocol sub-crates and provides full-stack
// poll/dispatch that ties them together.
//
// In single-queue mode (Tier 2), core 0 polls VirtIO and dispatches.
// Other cores process their inbox (populated by core 0).

#![no_std]
#![allow(static_mut_refs)]

extern crate drivers;
extern crate kernel;
pub extern crate net_types as types;
pub extern crate net_ethernet as ethernet;
pub extern crate net_arp as arp;
pub extern crate net_ipv4 as ipv4;
pub extern crate net_tcp as tcp;
pub extern crate net_udp as udp;
pub extern crate net_dhcp as dhcp;

/// Poll the network device and dispatch received frames through the
/// full stack: Ethernet -> ARP/IPv4 -> TCP/UDP.
///
/// In single-queue mode (Tier 2), only core 0 touches VirtIO.
/// All TCP/UDP processing currently runs on core 0.
pub fn poll() {
    // TODO: when multi-core TCP is ready, check cpu_id and only
    // poll VirtIO on core 0, process inbox on other cores.
    drivers::virtio_net::poll(net_receive);
}

fn net_receive(frame: &[u8]) {
    if let Some((ethertype, payload)) = ethernet::ethernet_parse(frame) {
        match ethertype {
            ethernet::ETHERTYPE_ARP => arp::arp_receive(payload),
            ethernet::ETHERTYPE_IPV4 => {
                if let Some(pkt) = ipv4::ipv4_receive(payload) {
                    match pkt.protocol {
                        ipv4::PROTO_TCP => tcp::tcp_receive(pkt.src, pkt.dst, pkt.payload),
                        ipv4::PROTO_UDP => udp::udp_receive(pkt.src, pkt.dst, pkt.payload),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}
