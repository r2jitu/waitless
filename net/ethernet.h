#pragma once
#include <stdint.h>
#include <stddef.h>
#include "net/types.h"

namespace net {
namespace ethernet {

struct EthernetHeader {
    MacAddr dst;
    MacAddr src;
    uint16_t ethertype; // network byte order
} __attribute__((packed));

static constexpr uint16_t ETHERTYPE_ARP  = 0x0806;
static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

// Send an ethernet frame. Prepends header and calls virtio_net::send().
void send(const MacAddr& dst, uint16_t ethertype, const void* payload, size_t len);

// Process a received ethernet frame. Dispatches to ARP or IPv4 handler.
void receive(const uint8_t* data, uint32_t len);

// Get our MAC address (cached from virtio_net::get_mac())
const MacAddr& our_mac();

} // namespace ethernet
} // namespace net
