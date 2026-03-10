#include "net/ethernet.h"
#include "drivers/virtio_net.h"
#include "kernel/serial.h"
#include "net/arp.h"
#include "net/ipv4.h"

extern "C" void *memcpy(void *dst, const void *src, size_t n);
extern "C" void *memset(void *dst, int c, size_t n);

namespace net {
namespace ethernet {

// Cached MAC address
static MacAddr cached_mac;
static bool mac_initialized = false;

const MacAddr &our_mac() {
  if (!mac_initialized) {
    const uint8_t *raw = virtio_net::get_mac();
    memcpy(cached_mac.bytes, raw, 6);
    mac_initialized = true;
  }
  return cached_mac;
}

// Static TX frame buffer: 14 (ETH) + 1500 (IP) = 1514.
// Single-threaded, non-reentrant on hot path.
static uint8_t eth_buf_[sizeof(EthernetHeader) + 1500];

void send(const MacAddr &dst, uint16_t ethertype, const void *payload,
          size_t len) {
  size_t frame_len = sizeof(EthernetHeader) + len;
  uint8_t *buf = eth_buf_;

  EthernetHeader *hdr = (EthernetHeader *)buf;
  memcpy(hdr->dst.bytes, dst.bytes, 6);
  memcpy(hdr->src.bytes, our_mac().bytes, 6);
  hdr->ethertype = htons(ethertype);

  if (payload && len > 0) {
    memcpy(buf + sizeof(EthernetHeader), payload, len);
  }

  virtio_net::send(buf, frame_len);
}

void receive(const uint8_t *data, uint32_t len) {
  if (len < sizeof(EthernetHeader)) {
    return;
  }

  const EthernetHeader *hdr = (const EthernetHeader *)data;
  uint16_t ethertype = ntohs(hdr->ethertype);

  const uint8_t *payload = data + sizeof(EthernetHeader);
  size_t payload_len = len - sizeof(EthernetHeader);

  switch (ethertype) {
  case ETHERTYPE_ARP:
    arp::receive(payload, payload_len);
    break;
  case ETHERTYPE_IPV4:
    ipv4::receive(payload, payload_len);
    break;
  default:
    // Unknown ethertype, drop
    break;
  }
}

} // namespace ethernet
} // namespace net
