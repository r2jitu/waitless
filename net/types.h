#pragma once
#include <stdint.h>
#include <stddef.h>

namespace net {

// Byte order conversion (network = big endian, host = little endian on x86)
static inline uint16_t htons(uint16_t h) {
    return __builtin_bswap16(h);
}
static inline uint16_t ntohs(uint16_t n) {
    return __builtin_bswap16(n);
}
static inline uint32_t htonl(uint32_t h) {
    return __builtin_bswap32(h);
}
static inline uint32_t ntohl(uint32_t n) {
    return __builtin_bswap32(n);
}

struct MacAddr {
    uint8_t bytes[6];
    bool operator==(const MacAddr& o) const;
    bool operator!=(const MacAddr& o) const;
    bool is_broadcast() const;
};

static constexpr MacAddr MAC_BROADCAST = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
static constexpr MacAddr MAC_ZERO = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

struct Ipv4Addr {
    uint32_t addr; // network byte order

    static Ipv4Addr from(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        return {(uint32_t)a | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24)};
    }
    bool operator==(const Ipv4Addr& o) const { return addr == o.addr; }
    bool operator!=(const Ipv4Addr& o) const { return addr != o.addr; }
};

static constexpr Ipv4Addr IP_ANY = {0};
static constexpr Ipv4Addr IP_BROADCAST = {0xFFFFFFFF};

// Network configuration (set by DHCP or static)
struct NetConfig {
    Ipv4Addr ip;
    Ipv4Addr subnet_mask;
    Ipv4Addr gateway;
    Ipv4Addr dns;
};

// Global network config
extern NetConfig config;

// Internet checksum (RFC 1071)
uint16_t checksum(const void* data, size_t len);

// Pseudo-header checksum for TCP/UDP
uint16_t tcp_checksum(Ipv4Addr src, Ipv4Addr dst, uint8_t proto,
                      const void* data, size_t len);

} // namespace net
