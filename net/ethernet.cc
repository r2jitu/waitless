#include "net/ethernet.h"
#include "net/arp.h"
#include "net/ipv4.h"
#include "kernel/mm.h"
#include "kernel/serial.h"
#include "drivers/virtio_net.h"

extern "C" void* memcpy(void* dst, const void* src, size_t n);
extern "C" void* memset(void* dst, int c, size_t n);

namespace net {
namespace ethernet {

// Cached MAC address
static MacAddr cached_mac;
static bool mac_initialized = false;

const MacAddr& our_mac() {
    if (!mac_initialized) {
        const uint8_t* raw = virtio_net::get_mac();
        memcpy(cached_mac.bytes, raw, 6);
        mac_initialized = true;
    }
    return cached_mac;
}

void send(const MacAddr& dst, uint16_t ethertype, const void* payload, size_t len) {
    size_t frame_len = sizeof(EthernetHeader) + len;
    uint8_t* buf = (uint8_t*)mm::kmalloc(frame_len);
    if (!buf) {
        serial::printf("ethernet: failed to allocate send buffer (%u bytes)\n",
                       (unsigned)frame_len);
        return;
    }

    EthernetHeader* hdr = (EthernetHeader*)buf;
    memcpy(hdr->dst.bytes, dst.bytes, 6);
    memcpy(hdr->src.bytes, our_mac().bytes, 6);
    hdr->ethertype = htons(ethertype);

    if (payload && len > 0) {
        memcpy(buf + sizeof(EthernetHeader), payload, len);
    }

    virtio_net::send(buf, frame_len);
    mm::kfree(buf);
}

void receive(const uint8_t* data, uint32_t len) {
    if (len < sizeof(EthernetHeader)) {
        return;
    }

    const EthernetHeader* hdr = (const EthernetHeader*)data;
    uint16_t ethertype = ntohs(hdr->ethertype);

    const uint8_t* payload = data + sizeof(EthernetHeader);
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
