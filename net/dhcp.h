#pragma once
#include "net/types.h"
#include <stddef.h>
#include <stdint.h>

namespace net {
namespace dhcp {

struct UdpHeader {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum; // 0 = no checksum
} __attribute__((packed));

struct DhcpPacket {
  uint8_t op;    // 1=request, 2=reply
  uint8_t htype; // 1=ethernet
  uint8_t hlen;  // 6
  uint8_t hops;  // 0
  uint32_t xid;  // transaction ID
  uint16_t secs;
  uint16_t flags;     // 0x8000 = broadcast
  uint32_t ciaddr;    // client IP (0 initially)
  uint32_t yiaddr;    // your IP (server fills)
  uint32_t siaddr;    // server IP
  uint32_t giaddr;    // gateway IP
  uint8_t chaddr[16]; // client hardware addr (MAC + padding)
  uint8_t sname[64];
  uint8_t file[128];
  uint32_t magic_cookie; // 0x63825363 (network byte order)
  uint8_t options[312];  // DHCP options
} __attribute__((packed));

// DHCP message types (option 53)
static constexpr uint8_t DHCP_DISCOVER = 1;
static constexpr uint8_t DHCP_OFFER = 2;
static constexpr uint8_t DHCP_REQUEST = 3;
static constexpr uint8_t DHCP_ACK = 5;
static constexpr uint8_t DHCP_NAK = 6;

// Perform DHCP discovery. Blocks until IP is obtained or timeout.
// Sets net::config with the obtained IP, subnet, gateway, DNS.
// Returns true on success.
bool discover();

} // namespace dhcp
} // namespace net
