#pragma once
#include <stdint.h>
#include <stddef.h>
#include "net/types.h"

namespace net {
namespace ipv4 {

struct Ipv4Header {
    uint8_t  version_ihl;   // version(4) | IHL(4), typically 0x45
    uint8_t  tos;
    uint16_t total_len;     // network byte order
    uint16_t id;
    uint16_t flags_frag;    // flags(3) | fragment_offset(13)
    uint8_t  ttl;
    uint8_t  protocol;      // 6=TCP, 17=UDP
    uint16_t checksum;
    Ipv4Addr src;
    Ipv4Addr dst;
} __attribute__((packed));

static constexpr uint8_t PROTO_TCP = 6;
static constexpr uint8_t PROTO_UDP = 17;

// Send an IP packet. Builds header, resolves MAC via ARP, sends via ethernet.
void send(Ipv4Addr dst, uint8_t protocol, const void* payload, size_t len);

// Process received IP packet. Dispatches to TCP or UDP handler.
void receive(const uint8_t* data, size_t len);

} // namespace ipv4
} // namespace net
