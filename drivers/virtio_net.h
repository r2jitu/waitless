#pragma once

// drivers/virtio_net.h -- Virtio network device driver
//
// This is the key driver of the unikernel: it provides DIRECT, in-process
// packet send/receive with ZERO syscall overhead. Applications call send()
// and poll() as regular function calls in the same address space and ring.
//
// The driver uses virtio legacy (0.9.5) PCI transport with split virtqueues:
//   Queue 0 = RX (receive) -- device writes incoming packets here
//   Queue 1 = TX (transmit) -- driver writes outgoing packets here
//
// Every packet in the virtqueue is prefixed with a VirtioNetHeader.
// The driver handles this transparently: send() prepends the header,
// poll() strips it before calling the user callback.

#include <stdint.h>
#include <stddef.h>

#include "drivers/pci.h"
#include "drivers/virtio.h"

namespace virtio_net {

// ============================================================================
// Feature bits
// ============================================================================

static constexpr uint32_t VIRTIO_NET_F_MAC       = (1 << 5);   // Device has MAC
static constexpr uint32_t VIRTIO_NET_F_STATUS    = (1 << 16);  // Config status field
static constexpr uint32_t VIRTIO_NET_F_MRG_RXBUF = (1 << 15);  // Merged RX buffers

// ============================================================================
// Virtio-net header (prepended to every packet on the wire)
// ============================================================================

struct VirtioNetHeader {
    uint8_t  flags;
    uint8_t  gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
    // Note: num_buffers (uint16_t) is only present when MRG_RXBUF is negotiated.
    // We reject MRG_RXBUF for simplicity, so it is not included here.
} __attribute__((packed));

// ============================================================================
// Constants
// ============================================================================

static constexpr int RX_BUFFERS  = 64;
static constexpr int BUFFER_SIZE = 2048; // Enough for max Ethernet frame + virtio header

// ============================================================================
// RX buffer layout
// ============================================================================

struct RxBuffer {
    VirtioNetHeader hdr;
    uint8_t data[BUFFER_SIZE - sizeof(VirtioNetHeader)];
} __attribute__((packed));

// ============================================================================
// Public interface -- direct function calls, no syscalls!
// ============================================================================

// Initialize the virtio-net device.
// Finds the PCI device, negotiates features, sets up RX/TX queues,
// reads the MAC address, populates RX buffers, and activates the device.
// Returns true on success.
bool init();

// Shut down the device by resetting it.
void shutdown();

// Get the 6-byte MAC address of the device.
const uint8_t* get_mac();

// Send an Ethernet frame.
// This is a DIRECT FUNCTION CALL -- no syscall, no mode switch!
// The driver prepends a VirtioNetHeader, enqueues the buffer in the TX queue,
// kicks the device, and polls until transmission completes.
// data: pointer to the Ethernet frame (starting with destination MAC)
// len:  length of the Ethernet frame in bytes
void send(const void* data, uint32_t len);

// Poll for received packets.
// Checks the RX used ring for completed buffers. For each received packet,
// calls callback(data, len) where data points to the Ethernet frame
// (past the virtio header) and len is the frame length.
// Re-arms the RX buffer after the callback returns.
// Returns the number of packets processed in this call.
int poll(void (*callback)(const uint8_t* data, uint32_t len));

} // namespace virtio_net
