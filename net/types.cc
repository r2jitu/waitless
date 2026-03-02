#include "net/types.h"

extern "C" void* memcpy(void* dst, const void* src, size_t n);
extern "C" void* memset(void* dst, int c, size_t n);

namespace net {

// Global network configuration
NetConfig config = {IP_ANY, IP_ANY, IP_ANY, IP_ANY};

bool MacAddr::operator==(const MacAddr& o) const {
    return bytes[0] == o.bytes[0] && bytes[1] == o.bytes[1] &&
           bytes[2] == o.bytes[2] && bytes[3] == o.bytes[3] &&
           bytes[4] == o.bytes[4] && bytes[5] == o.bytes[5];
}

bool MacAddr::operator!=(const MacAddr& o) const {
    return !(*this == o);
}

bool MacAddr::is_broadcast() const {
    return bytes[0] == 0xFF && bytes[1] == 0xFF && bytes[2] == 0xFF &&
           bytes[3] == 0xFF && bytes[4] == 0xFF && bytes[5] == 0xFF;
}

// Internet checksum (RFC 1071)
// Sum all 16-bit words, fold carries, return one's complement.
uint16_t checksum(const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    uint32_t sum = 0;

    // Sum 16-bit words
    while (len > 1) {
        uint16_t word = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        sum += word;
        p += 2;
        len -= 2;
    }

    // Handle odd byte
    if (len == 1) {
        sum += (uint16_t)p[0];
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// Pseudo-header checksum for TCP/UDP.
// Prepend pseudo-header (src_ip, dst_ip, zero, protocol, length) then checksum.
uint16_t tcp_checksum(Ipv4Addr src, Ipv4Addr dst, uint8_t proto,
                      const void* data, size_t len) {
    // Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + length(2) = 12 bytes
    struct PseudoHeader {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t length;
    } __attribute__((packed));

    // Compute checksum over pseudo-header + data combined.
    // We accumulate the sum manually to avoid allocating a combined buffer.
    uint32_t sum = 0;

    // Add pseudo-header fields
    PseudoHeader ph;
    ph.src = src.addr;
    ph.dst = dst.addr;
    ph.zero = 0;
    ph.proto = proto;
    ph.length = htons((uint16_t)len);

    const uint8_t* phb = (const uint8_t*)&ph;
    for (size_t i = 0; i < sizeof(PseudoHeader); i += 2) {
        uint16_t word = (uint16_t)phb[i] | ((uint16_t)phb[i + 1] << 8);
        sum += word;
    }

    // Add data
    const uint8_t* p = (const uint8_t*)data;
    size_t remaining = len;
    while (remaining > 1) {
        uint16_t word = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        sum += word;
        p += 2;
        remaining -= 2;
    }
    if (remaining == 1) {
        sum += (uint16_t)p[0];
    }

    // Fold carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

} // namespace net
