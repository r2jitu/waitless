#include "net/dhcp.h"
#include "net/ethernet.h"
#include "net/ipv4.h"
#include "net/arp.h"
#include "kernel/arch.h"
#include "kernel/mm.h"
#include "kernel/serial.h"
#include "drivers/virtio_net.h"

extern "C" void* memcpy(void* dst, const void* src, size_t n);
extern "C" void* memset(void* dst, int c, size_t n);

namespace net {
namespace dhcp {

// Transaction ID counter
static uint32_t xid_counter = 0x12345678;

// State for the current DHCP exchange
static bool got_offer = false;
static bool got_ack = false;
static Ipv4Addr offered_ip;
static Ipv4Addr offered_subnet;
static Ipv4Addr offered_gateway;
static Ipv4Addr offered_dns;
static Ipv4Addr offered_server_ip;
static uint32_t current_xid = 0;

// Build a raw DHCP frame: [EthernetHeader][Ipv4Header][UdpHeader][DhcpPacket]
// Returns total frame size, or 0 on error.
// The caller must free the returned buffer.
static uint8_t* build_dhcp_frame(const DhcpPacket* dhcp_pkt,
                                  size_t dhcp_len, size_t* out_frame_len) {
    using namespace net::ethernet;
    using namespace net::ipv4;

    size_t udp_len = sizeof(UdpHeader) + dhcp_len;
    size_t ip_len = sizeof(Ipv4Header) + udp_len;
    size_t frame_len = sizeof(EthernetHeader) + ip_len;

    uint8_t* buf = (uint8_t*)mm::kmalloc(frame_len);
    if (!buf) return nullptr;
    memset(buf, 0, frame_len);

    // Ethernet header
    EthernetHeader* eth = (EthernetHeader*)buf;
    memset(eth->dst.bytes, 0xFF, 6); // broadcast
    memcpy(eth->src.bytes, ethernet::our_mac().bytes, 6);
    eth->ethertype = htons(ETHERTYPE_IPV4);

    // IP header
    Ipv4Header* ip = (Ipv4Header*)(buf + sizeof(EthernetHeader));
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_len = htons((uint16_t)ip_len);
    ip->id = htons(1);
    ip->flags_frag = 0;
    ip->ttl = 64;
    ip->protocol = PROTO_UDP;
    ip->checksum = 0;
    ip->src = IP_ANY;       // 0.0.0.0 — we don't have an IP yet
    ip->dst = IP_BROADCAST; // 255.255.255.255
    ip->checksum = checksum(ip, sizeof(Ipv4Header));

    // UDP header
    UdpHeader* udp = (UdpHeader*)((uint8_t*)ip + sizeof(Ipv4Header));
    udp->src_port = htons(68); // DHCP client
    udp->dst_port = htons(67); // DHCP server
    udp->length = htons((uint16_t)udp_len);
    udp->checksum = 0; // UDP checksum optional for IPv4

    // DHCP payload
    memcpy((uint8_t*)udp + sizeof(UdpHeader), dhcp_pkt, dhcp_len);

    *out_frame_len = frame_len;
    return buf;
}

// Parse DHCP options from a received DHCP packet.
// Extracts message type, subnet mask, router, DNS, server identifier.
static uint8_t parse_options(const DhcpPacket* pkt,
                              Ipv4Addr* subnet, Ipv4Addr* router,
                              Ipv4Addr* dns, Ipv4Addr* server_id) {
    uint8_t msg_type = 0;
    subnet->addr = 0;
    router->addr = 0;
    dns->addr = 0;
    server_id->addr = 0;

    const uint8_t* opts = pkt->options;
    size_t i = 0;

    while (i < sizeof(pkt->options)) {
        uint8_t opt = opts[i++];
        if (opt == 255) break;  // End option
        if (opt == 0) continue; // Padding

        if (i >= sizeof(pkt->options)) break;
        uint8_t opt_len = opts[i++];
        if (i + opt_len > sizeof(pkt->options)) break;

        switch (opt) {
        case 1: // Subnet mask
            if (opt_len >= 4) {
                memcpy(&subnet->addr, &opts[i], 4);
            }
            break;
        case 3: // Router
            if (opt_len >= 4) {
                memcpy(&router->addr, &opts[i], 4);
            }
            break;
        case 6: // DNS
            if (opt_len >= 4) {
                memcpy(&dns->addr, &opts[i], 4);
            }
            break;
        case 53: // DHCP message type
            if (opt_len >= 1) {
                msg_type = opts[i];
            }
            break;
        case 54: // Server identifier
            if (opt_len >= 4) {
                memcpy(&server_id->addr, &opts[i], 4);
            }
            break;
        }

        i += opt_len;
    }

    return msg_type;
}

// Callback for handling DHCP responses during polling.
// This processes raw ethernet frames looking for DHCP replies.
static void dhcp_receive(const uint8_t* data, uint32_t len) {
    using namespace net::ethernet;
    using namespace net::ipv4;

    // Minimum: Ethernet + IP + UDP + partial DHCP
    if (len < sizeof(EthernetHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader) + 240) {
        return;
    }

    const EthernetHeader* eth = (const EthernetHeader*)data;
    uint16_t ethertype = ntohs(eth->ethertype);
    if (ethertype != ETHERTYPE_IPV4) {
        // Still process ARP to help with resolution
        if (ethertype == ETHERTYPE_ARP) {
            arp::receive(data + sizeof(EthernetHeader),
                         len - sizeof(EthernetHeader));
        }
        return;
    }

    const Ipv4Header* ip = (const Ipv4Header*)(data + sizeof(EthernetHeader));
    if (ip->protocol != PROTO_UDP) {
        return;
    }

    size_t ip_hdr_len = (size_t)(ip->version_ihl & 0x0F) * 4;
    const UdpHeader* udp = (const UdpHeader*)((const uint8_t*)ip + ip_hdr_len);

    // Check it's a DHCP reply (from server port 67 to client port 68)
    if (ntohs(udp->src_port) != 67 || ntohs(udp->dst_port) != 68) {
        return;
    }

    const DhcpPacket* pkt = (const DhcpPacket*)((const uint8_t*)udp + sizeof(UdpHeader));

    // Verify this is a reply and matches our transaction ID
    if (pkt->op != 2) return; // Not a reply
    if (pkt->xid != current_xid) return; // Not our transaction

    // Verify magic cookie
    if (ntohl(pkt->magic_cookie) != 0x63825363) return;

    // Parse options
    Ipv4Addr subnet, router, dns, server_id;
    uint8_t msg_type = parse_options(pkt, &subnet, &router, &dns, &server_id);

    if (msg_type == DHCP_OFFER && !got_offer) {
        offered_ip.addr = pkt->yiaddr;
        offered_subnet = subnet;
        offered_gateway = router;
        offered_dns = dns;
        offered_server_ip = server_id;
        got_offer = true;

        serial::printf("dhcp: offer received: %d.%d.%d.%d\n",
                       offered_ip.addr & 0xFF,
                       (offered_ip.addr >> 8) & 0xFF,
                       (offered_ip.addr >> 16) & 0xFF,
                       (offered_ip.addr >> 24) & 0xFF);
    } else if (msg_type == DHCP_ACK && !got_ack) {
        // Update with ACK values (may differ from offer)
        offered_ip.addr = pkt->yiaddr;
        if (subnet.addr != 0) offered_subnet = subnet;
        if (router.addr != 0) offered_gateway = router;
        if (dns.addr != 0) offered_dns = dns;
        got_ack = true;

        serial::printf("dhcp: ACK received: %d.%d.%d.%d\n",
                       offered_ip.addr & 0xFF,
                       (offered_ip.addr >> 8) & 0xFF,
                       (offered_ip.addr >> 16) & 0xFF,
                       (offered_ip.addr >> 24) & 0xFF);
    } else if (msg_type == DHCP_NAK) {
        serial::printf("dhcp: NAK received, discovery failed\n");
    }
}

static void build_base_packet(DhcpPacket* pkt) {
    memset(pkt, 0, sizeof(DhcpPacket));
    pkt->op = 1;      // BOOTREQUEST
    pkt->htype = 1;   // Ethernet
    pkt->hlen = 6;
    pkt->hops = 0;
    pkt->xid = current_xid;
    pkt->secs = 0;
    pkt->flags = htons(0x8000); // Broadcast flag
    pkt->ciaddr = 0;
    pkt->yiaddr = 0;
    pkt->siaddr = 0;
    pkt->giaddr = 0;
    memcpy(pkt->chaddr, ethernet::our_mac().bytes, 6);
    pkt->magic_cookie = htonl(0x63825363);
}

static bool send_discover() {
    DhcpPacket pkt;
    build_base_packet(&pkt);

    // Options
    size_t oi = 0;
    // Option 53: DHCP message type = DISCOVER
    pkt.options[oi++] = 53;
    pkt.options[oi++] = 1;
    pkt.options[oi++] = DHCP_DISCOVER;

    // Option 55: Parameter request list
    pkt.options[oi++] = 55;
    pkt.options[oi++] = 4;
    pkt.options[oi++] = 1;   // Subnet mask
    pkt.options[oi++] = 3;   // Router
    pkt.options[oi++] = 6;   // DNS
    pkt.options[oi++] = 15;  // Domain name

    // End option
    pkt.options[oi++] = 255;

    size_t frame_len = 0;
    uint8_t* frame = build_dhcp_frame(&pkt, sizeof(DhcpPacket), &frame_len);
    if (!frame) return false;

    virtio_net::send(frame, frame_len);
    mm::kfree(frame);
    return true;
}

static bool send_request() {
    DhcpPacket pkt;
    build_base_packet(&pkt);

    // Options
    size_t oi = 0;
    // Option 53: DHCP message type = REQUEST
    pkt.options[oi++] = 53;
    pkt.options[oi++] = 1;
    pkt.options[oi++] = DHCP_REQUEST;

    // Option 50: Requested IP address
    pkt.options[oi++] = 50;
    pkt.options[oi++] = 4;
    memcpy(&pkt.options[oi], &offered_ip.addr, 4);
    oi += 4;

    // Option 54: Server identifier
    pkt.options[oi++] = 54;
    pkt.options[oi++] = 4;
    memcpy(&pkt.options[oi], &offered_server_ip.addr, 4);
    oi += 4;

    // Option 55: Parameter request list
    pkt.options[oi++] = 55;
    pkt.options[oi++] = 4;
    pkt.options[oi++] = 1;   // Subnet mask
    pkt.options[oi++] = 3;   // Router
    pkt.options[oi++] = 6;   // DNS
    pkt.options[oi++] = 15;  // Domain name

    // End option
    pkt.options[oi++] = 255;

    size_t frame_len = 0;
    uint8_t* frame = build_dhcp_frame(&pkt, sizeof(DhcpPacket), &frame_len);
    if (!frame) return false;

    virtio_net::send(frame, frame_len);
    mm::kfree(frame);
    return true;
}

// Poll for DHCP response with a real time-based timeout.
// On hardware-accelerated VZ, iteration-based loops complete in microseconds
// because each poll() is just a memory read at native CPU speed.
// Using arch::udelay() ensures the timeout is reliable across TCG and HW accel.
static void dhcp_poll_wait(bool* flag, int timeout_ms) {
    // Poll in 1ms increments until timeout or flag is set.
    for (int ms = 0; ms < timeout_ms && !*flag; ms++) {
        // Do a batch of polls per ms to keep latency low
        for (int i = 0; i < 100 && !*flag; i++) {
            virtio_net::poll(dhcp_receive);
        }
        arch::udelay(1000); // 1ms
    }
}

bool discover() {
    static constexpr int MAX_RETRIES = 5;
    static constexpr int RETRY_TIMEOUT_MS = 2000; // 2 seconds per retry

    serial::printf("dhcp: starting discovery...\n");

    // Reset state
    got_offer = false;
    got_ack = false;
    current_xid = htonl(xid_counter++);

    // Phase 1: DHCP DISCOVER -> OFFER
    for (int retry = 0; retry < MAX_RETRIES && !got_offer; retry++) {
        serial::printf("dhcp: sending DISCOVER (attempt %d/%d)\n",
                       retry + 1, MAX_RETRIES);
        if (!send_discover()) {
            serial::printf("dhcp: failed to build discover packet\n");
            return false;
        }

        dhcp_poll_wait(&got_offer, RETRY_TIMEOUT_MS);
    }

    if (!got_offer) {
        serial::printf("dhcp: no offer received, giving up\n");
        return false;
    }

    // Phase 2: DHCP REQUEST -> ACK
    for (int retry = 0; retry < MAX_RETRIES && !got_ack; retry++) {
        serial::printf("dhcp: sending REQUEST (attempt %d/%d)\n",
                       retry + 1, MAX_RETRIES);
        if (!send_request()) {
            serial::printf("dhcp: failed to build request packet\n");
            return false;
        }

        dhcp_poll_wait(&got_ack, RETRY_TIMEOUT_MS);
    }

    if (!got_ack) {
        serial::printf("dhcp: no ACK received, giving up\n");
        return false;
    }

    // Apply configuration
    config.ip = offered_ip;
    config.subnet_mask = offered_subnet;
    config.gateway = offered_gateway;
    config.dns = offered_dns;

    serial::printf("dhcp: configured IP %d.%d.%d.%d\n",
                   config.ip.addr & 0xFF,
                   (config.ip.addr >> 8) & 0xFF,
                   (config.ip.addr >> 16) & 0xFF,
                   (config.ip.addr >> 24) & 0xFF);
    serial::printf("dhcp: subnet %d.%d.%d.%d\n",
                   config.subnet_mask.addr & 0xFF,
                   (config.subnet_mask.addr >> 8) & 0xFF,
                   (config.subnet_mask.addr >> 16) & 0xFF,
                   (config.subnet_mask.addr >> 24) & 0xFF);
    serial::printf("dhcp: gateway %d.%d.%d.%d\n",
                   config.gateway.addr & 0xFF,
                   (config.gateway.addr >> 8) & 0xFF,
                   (config.gateway.addr >> 16) & 0xFF,
                   (config.gateway.addr >> 24) & 0xFF);
    serial::printf("dhcp: DNS %d.%d.%d.%d\n",
                   config.dns.addr & 0xFF,
                   (config.dns.addr >> 8) & 0xFF,
                   (config.dns.addr >> 16) & 0xFF,
                   (config.dns.addr >> 24) & 0xFF);

    // Send gratuitous ARP to announce our IP
    arp::announce();

    return true;
}

} // namespace dhcp
} // namespace net
