#include "net/ipv4.h"
#include "kernel/serial.h"
#include "net/arp.h"
#include "net/ethernet.h"
#include "net/tcp.h"

extern "C" void *memcpy(void *dst, const void *src, size_t n);
extern "C" void *memset(void *dst, int c, size_t n);

namespace net {
namespace ipv4 {

// Incrementing packet ID counter
static uint16_t next_id = 1;

// Static TX buffer: max IP packet = 20 (IP) + 20 (TCP) + 1460 (MSS) = 1500.
// Single-threaded, non-reentrant on hot path (gateway ARP cached).
static uint8_t ip_buf_[sizeof(Ipv4Header) + 1480];

void send(Ipv4Addr dst, uint8_t protocol, const void *payload, size_t len) {
  size_t total_len = sizeof(Ipv4Header) + len;
  uint8_t *buf = ip_buf_;

  Ipv4Header *hdr = (Ipv4Header *)buf;
  hdr->version_ihl = 0x45; // IPv4, IHL=5 (20 bytes, no options)
  hdr->tos = 0;
  hdr->total_len = htons((uint16_t)total_len);
  hdr->id = htons(next_id++);
  hdr->flags_frag = htons(0x4000); // Don't Fragment flag set
  hdr->ttl = 64;
  hdr->protocol = protocol;
  hdr->checksum = 0;
  hdr->src = config.ip;
  hdr->dst = dst;

  // Compute IP header checksum (over header only, 20 bytes)
  hdr->checksum = checksum(hdr, sizeof(Ipv4Header));

  // Copy payload after header
  if (payload && len > 0) {
    memcpy(buf + sizeof(Ipv4Header), payload, len);
  }

  // Determine next-hop: if on same subnet, send directly; otherwise use gateway
  Ipv4Addr next_hop;
  if (dst == IP_BROADCAST) {
    // Broadcast goes directly on the local network
    ethernet::send(MAC_BROADCAST, ethernet::ETHERTYPE_IPV4, buf, total_len);
    return;
  }

  if ((dst.addr & config.subnet_mask.addr) ==
      (config.ip.addr & config.subnet_mask.addr)) {
    next_hop = dst;
  } else {
    next_hop = config.gateway;
  }

  // Resolve next-hop MAC via ARP
  MacAddr dst_mac = arp::resolve(next_hop);

  ethernet::send(dst_mac, ethernet::ETHERTYPE_IPV4, buf, total_len);
}

void receive(const uint8_t *data, size_t len) {
  if (len < sizeof(Ipv4Header)) {
    return;
  }

  const Ipv4Header *hdr = (const Ipv4Header *)data;

  // Check version == 4
  uint8_t version = (hdr->version_ihl >> 4) & 0x0F;
  if (version != 4) {
    return;
  }

  // Get IHL (header length in 32-bit words)
  uint8_t ihl = hdr->version_ihl & 0x0F;
  if (ihl < 5) {
    return;
  }
  size_t header_len = (size_t)ihl * 4;

  // Verify total length
  uint16_t total_len = ntohs(hdr->total_len);
  if (total_len < header_len || total_len > len) {
    return;
  }

  // Verify header checksum
  // Make a copy to zero out checksum field for verification
  uint8_t hdr_copy[60]; // max IP header size
  if (header_len > sizeof(hdr_copy)) {
    return;
  }
  memcpy(hdr_copy, hdr, header_len);
  ((Ipv4Header *)hdr_copy)->checksum = 0;
  uint16_t computed = checksum(hdr_copy, header_len);
  if (computed != hdr->checksum) {
    // Checksum mismatch, drop
    return;
  }

  // Check destination: must be for us or broadcast
  if (hdr->dst != config.ip && hdr->dst != IP_BROADCAST &&
      config.ip != IP_ANY) {
    return;
  }

  // Extract payload
  const uint8_t *payload = data + header_len;
  size_t payload_len = total_len - header_len;

  // Dispatch based on protocol
  switch (hdr->protocol) {
  case PROTO_TCP:
    tcp::receive(hdr->src, payload, payload_len);
    break;
  case PROTO_UDP:
    // UDP handler not yet implemented via the stack;
    // DHCP handles raw UDP packets directly.
    break;
  default:
    break;
  }
}

} // namespace ipv4
} // namespace net
