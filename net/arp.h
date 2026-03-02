#pragma once
#include <stdint.h>
#include <stddef.h>
#include "net/types.h"

namespace net {
namespace arp {

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunaligned-access"
struct ArpPacket {
    uint16_t hw_type;      // 1 = Ethernet
    uint16_t proto_type;   // 0x0800 = IPv4
    uint8_t  hw_len;       // 6
    uint8_t  proto_len;    // 4
    uint16_t operation;    // 1 = request, 2 = reply
    MacAddr  sender_mac;
    Ipv4Addr sender_ip;
    MacAddr  target_mac;
    Ipv4Addr target_ip;
} __attribute__((packed));
#pragma GCC diagnostic pop

static constexpr uint16_t OP_REQUEST = 1;
static constexpr uint16_t OP_REPLY   = 2;

// Handle incoming ARP packet
void receive(const uint8_t* data, size_t len);

// Send ARP request for the given IP
void request(Ipv4Addr ip);

// Look up MAC in ARP cache. Returns true if found.
bool lookup(Ipv4Addr ip, MacAddr* mac);

// Resolve IP to MAC address. Blocks with polling and timeout.
// Returns broadcast MAC on failure.
MacAddr resolve(Ipv4Addr ip);

// Send a gratuitous ARP announcement for our IP
void announce();

} // namespace arp
} // namespace net
