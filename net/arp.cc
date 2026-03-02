#include "net/arp.h"
#include "net/ethernet.h"
#include "kernel/mm.h"
#include "kernel/serial.h"
#include "drivers/virtio_net.h"

extern "C" void* memcpy(void* dst, const void* src, size_t n);
extern "C" void* memset(void* dst, int c, size_t n);

namespace net {
namespace arp {

// ARP cache entry
struct CacheEntry {
    Ipv4Addr ip;
    MacAddr mac;
    bool valid;
};

static constexpr int ARP_CACHE_SIZE = 64;
static CacheEntry cache[ARP_CACHE_SIZE];
static bool cache_initialized = false;

static void init_cache() {
    if (!cache_initialized) {
        memset(cache, 0, sizeof(cache));
        cache_initialized = true;
    }
}

static void cache_update(Ipv4Addr ip, const MacAddr& mac) {
    init_cache();

    // Check if entry already exists
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].ip == ip) {
            memcpy(cache[i].mac.bytes, mac.bytes, 6);
            return;
        }
    }

    // Find a free slot
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!cache[i].valid) {
            cache[i].ip = ip;
            memcpy(cache[i].mac.bytes, mac.bytes, 6);
            cache[i].valid = true;
            return;
        }
    }

    // Cache full: overwrite first entry (simple eviction)
    cache[0].ip = ip;
    memcpy(cache[0].mac.bytes, mac.bytes, 6);
    cache[0].valid = true;
}

bool lookup(Ipv4Addr ip, MacAddr* mac) {
    init_cache();

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].ip == ip) {
            memcpy(mac->bytes, cache[i].mac.bytes, 6);
            return true;
        }
    }
    return false;
}

void receive(const uint8_t* data, size_t len) {
    if (len < sizeof(ArpPacket)) {
        return;
    }

    const ArpPacket* pkt = (const ArpPacket*)data;

    // Validate hardware type (Ethernet) and protocol type (IPv4)
    if (ntohs(pkt->hw_type) != 1 || ntohs(pkt->proto_type) != 0x0800) {
        return;
    }
    if (pkt->hw_len != 6 || pkt->proto_len != 4) {
        return;
    }

    // Gratuitous learning: always update cache with sender's info
    cache_update(pkt->sender_ip, pkt->sender_mac);

    uint16_t op = ntohs(pkt->operation);

    if (op == OP_REQUEST) {
        // If they're asking for our MAC, send a reply
        if (pkt->target_ip == config.ip && config.ip != IP_ANY) {
            ArpPacket reply;
            reply.hw_type = htons(1);
            reply.proto_type = htons(0x0800);
            reply.hw_len = 6;
            reply.proto_len = 4;
            reply.operation = htons(OP_REPLY);
            memcpy(reply.sender_mac.bytes, ethernet::our_mac().bytes, 6);
            reply.sender_ip = config.ip;
            memcpy(reply.target_mac.bytes, pkt->sender_mac.bytes, 6);
            reply.target_ip = pkt->sender_ip;

            ethernet::send(pkt->sender_mac, ethernet::ETHERTYPE_ARP,
                           &reply, sizeof(reply));
        }
    }
    // For OP_REPLY, the cache was already updated above via gratuitous learning
}

void request(Ipv4Addr ip) {
    ArpPacket pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.hw_type = htons(1);
    pkt.proto_type = htons(0x0800);
    pkt.hw_len = 6;
    pkt.proto_len = 4;
    pkt.operation = htons(OP_REQUEST);
    memcpy(pkt.sender_mac.bytes, ethernet::our_mac().bytes, 6);
    pkt.sender_ip = config.ip;
    memset(pkt.target_mac.bytes, 0, 6);
    pkt.target_ip = ip;

    ethernet::send(MAC_BROADCAST, ethernet::ETHERTYPE_ARP, &pkt, sizeof(pkt));
}

MacAddr resolve(Ipv4Addr ip) {
    // Broadcast and zero addresses
    if (ip == IP_BROADCAST) {
        return MAC_BROADCAST;
    }

    // Check cache first
    MacAddr mac;
    if (lookup(ip, &mac)) {
        return mac;
    }

    // Send ARP request and poll for reply
    // Retry up to 3 times with ~2 second timeout each (approximated by poll iterations)
    static constexpr int MAX_RETRIES = 3;
    static constexpr int POLLS_PER_RETRY = 200000;

    for (int retry = 0; retry < MAX_RETRIES; retry++) {
        request(ip);

        for (int i = 0; i < POLLS_PER_RETRY; i++) {
            // Poll the network device for incoming packets
            virtio_net::poll(ethernet::receive);

            // Check if the ARP reply arrived
            if (lookup(ip, &mac)) {
                return mac;
            }
        }

        serial::printf("arp: resolve retry %d for %d.%d.%d.%d\n", retry + 1,
                       ip.addr & 0xFF, (ip.addr >> 8) & 0xFF,
                       (ip.addr >> 16) & 0xFF, (ip.addr >> 24) & 0xFF);
    }

    serial::printf("arp: failed to resolve %d.%d.%d.%d, using broadcast\n",
                   ip.addr & 0xFF, (ip.addr >> 8) & 0xFF,
                   (ip.addr >> 16) & 0xFF, (ip.addr >> 24) & 0xFF);
    return MAC_BROADCAST;
}

void announce() {
    // Gratuitous ARP: sender and target IP are both our IP
    ArpPacket pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.hw_type = htons(1);
    pkt.proto_type = htons(0x0800);
    pkt.hw_len = 6;
    pkt.proto_len = 4;
    pkt.operation = htons(OP_REQUEST);
    memcpy(pkt.sender_mac.bytes, ethernet::our_mac().bytes, 6);
    pkt.sender_ip = config.ip;
    memset(pkt.target_mac.bytes, 0xFF, 6);
    pkt.target_ip = config.ip;

    ethernet::send(MAC_BROADCAST, ethernet::ETHERTYPE_ARP, &pkt, sizeof(pkt));
}

} // namespace arp
} // namespace net
