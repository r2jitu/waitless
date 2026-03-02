#pragma once

// drivers/virtio.h -- Virtio transport layer and split virtqueue
//
// Supports two transports:
//   PCI (legacy 0.9.5): used on x86_64 via I/O ports; on ARM64 via PCI I/O MMIO.
//   MMIO (legacy v1):   used on ARM64 via virtio-net-device (no PCI bus needed).
//
// This is a library layer: applications and higher-level drivers (like
// virtio_net) call these functions directly -- no syscalls, no mode switches.
//
// Reference: Virtual I/O Device (VIRTIO) Version 0.9.5 / MMIO transport spec

#include <stdint.h>
#include <stddef.h>

#include "drivers/pci.h"

namespace virtio {

// ============================================================================
// Legacy (0.9.5) PCI I/O register offsets (relative to BAR0)
// ============================================================================

static constexpr uint16_t REG_DEVICE_FEATURES = 0x00; // 32-bit read
static constexpr uint16_t REG_GUEST_FEATURES  = 0x04; // 32-bit write
static constexpr uint16_t REG_QUEUE_ADDRESS   = 0x08; // 32-bit, physical >> 12
static constexpr uint16_t REG_QUEUE_SIZE      = 0x0C; // 16-bit read
static constexpr uint16_t REG_QUEUE_SELECT    = 0x0E; // 16-bit write
static constexpr uint16_t REG_QUEUE_NOTIFY    = 0x10; // 16-bit write
static constexpr uint16_t REG_DEVICE_STATUS   = 0x12; // 8-bit
static constexpr uint16_t REG_ISR_STATUS      = 0x13; // 8-bit read
static constexpr uint16_t REG_DEVICE_CONFIG   = 0x14; // device-specific config

// ============================================================================
// Device status bits
// ============================================================================

static constexpr uint8_t STATUS_ACKNOWLEDGE = 1;
static constexpr uint8_t STATUS_DRIVER      = 2;
static constexpr uint8_t STATUS_DRIVER_OK   = 4;
static constexpr uint8_t STATUS_FEATURES_OK = 8;
static constexpr uint8_t STATUS_FAILED      = 128;

// ============================================================================
// Virtqueue descriptor flags
// ============================================================================

static constexpr uint16_t VIRTQ_DESC_F_NEXT  = 1; // Descriptor is chained
static constexpr uint16_t VIRTQ_DESC_F_WRITE = 2; // Buffer is device-writable

// Available ring flag
static constexpr uint16_t VIRTQ_AVAIL_F_NO_INTERRUPT = 1;

// ============================================================================
// Virtio-MMIO transport register offsets (relative to device base address)
//
// QEMU virt machine maps the first virtio-mmio device at 0x0a000000.
// All registers are 32-bit, memory-mapped.  Legacy (version 1) protocol.
// ============================================================================

namespace mmio {
    static constexpr uint64_t BASE           = 0x0a000000ULL;
    // Register offsets (all 32-bit)
    static constexpr uint32_t MAGIC_VALUE    = 0x000; // "virt" = 0x74726976 (read)
    static constexpr uint32_t VERSION        = 0x004; // 1 = legacy           (read)
    static constexpr uint32_t DEVICE_ID      = 0x008; // 1=net, 2=blk …      (read)
    static constexpr uint32_t HOST_FEATURES  = 0x010; // device feature bits  (read)
    static constexpr uint32_t GUEST_FEATURES = 0x020; // driver feature bits  (write)
    static constexpr uint32_t GUEST_PAGE_SIZE= 0x028; // must write 4096      (write)
    static constexpr uint32_t QUEUE_SEL      = 0x030; // queue selector       (write)
    static constexpr uint32_t QUEUE_NUM_MAX  = 0x034; // max queue size       (read)
    static constexpr uint32_t QUEUE_NUM      = 0x038; // chosen queue size    (write)
    static constexpr uint32_t QUEUE_ALIGN    = 0x03c; // must write 4096      (write)
    static constexpr uint32_t QUEUE_PFN      = 0x040; // phys addr >> 12      (r/w)
    static constexpr uint32_t QUEUE_NOTIFY   = 0x050; // queue kick           (write)
    static constexpr uint32_t STATUS         = 0x070; // device status        (r/w)
    static constexpr uint32_t DEVICE_CONFIG  = 0x100; // device-specific config
    static constexpr uint32_t MAGIC          = 0x74726976u; // "virt"
} // namespace mmio

// ============================================================================
// Split virtqueue data structures (must match hardware layout exactly)
// ============================================================================

// A single descriptor in the descriptor table.
// Each descriptor points to a buffer and optionally chains to the next.
struct VirtqDesc {
    uint64_t addr;   // Physical address of the buffer
    uint32_t len;    // Length of the buffer in bytes
    uint16_t flags;  // VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE
    uint16_t next;   // Index of next descriptor if NEXT flag is set
} __attribute__((packed));

// The available ring: driver writes descriptor indices here for the device.
struct VirtqAvail {
    uint16_t flags;  // VIRTQ_AVAIL_F_NO_INTERRUPT
    uint16_t idx;    // Next index the driver will write to
    uint16_t ring[]; // Array of descriptor chain head indices
} __attribute__((packed));

// A single element in the used ring.
struct VirtqUsedElem {
    uint32_t id;  // Descriptor chain head index
    uint32_t len; // Total bytes written by the device
} __attribute__((packed));

// The used ring: device writes completed descriptor indices here.
struct VirtqUsed {
    uint16_t flags;
    uint16_t idx;          // Next index the device will write to
    VirtqUsedElem ring[];  // Completed descriptors
} __attribute__((packed));

// ============================================================================
// Virtqueue class
// ============================================================================

class Virtqueue {
public:
    // Initialize the virtqueue for a given queue index.
    // Selects the queue, reads its size, allocates physically contiguous memory,
    // sets up the descriptor table / available ring / used ring, and tells the
    // device where the queue lives.
    //
    // base:        BAR0 base — I/O port (x86_64) or MMIO address (aarch64/PCI)
    //              For is_mmio=true, base is the virtio-mmio device base (e.g. 0x0a000000).
    // queue_index: which virtqueue (0 = RX, 1 = TX, etc.)
    // is_mmio:     true  = virtio-mmio transport (ARM64, virtio-net-device)
    //              false = virtio-PCI legacy transport (default)
    //
    // Returns true on success.
    bool init(uint16_t queue_size, uint64_t base, uint16_t queue_index,
              bool is_mmio = false);

    // Add a buffer chain to the available ring.
    //
    // buffers: array of buffer pointers (physical addresses)
    // lengths: array of buffer lengths
    // out_count: number of device-readable (output) buffers, placed first
    // in_count: number of device-writable (input) buffers, placed after
    //
    // Returns the head descriptor index, or -1 if not enough free descriptors.
    int add_buf(void** buffers, uint32_t* lengths, int out_count, int in_count);

    // Notify the device that new buffers are available in the ring.
    void kick();

    // Check for completed buffers in the used ring.
    // If a used entry is available, sets *id to the descriptor chain head index
    // and *len to the number of bytes written, then returns true.
    // Returns false if no used entries are pending.
    bool get_used(uint16_t* id, uint32_t* len);

    uint16_t size() const { return queue_size_; }

    // Get the descriptor at a given index (for reading buffer addresses)
    VirtqDesc* desc(uint16_t idx) { return &descs_[idx]; }

private:
    VirtqDesc*  descs_  = nullptr;  // Descriptor table
    VirtqAvail* avail_  = nullptr;  // Available ring
    VirtqUsed*  used_   = nullptr;  // Used ring
    uint16_t queue_size_    = 0;    // Number of descriptors
    uint16_t free_head_     = 0;    // Head of free descriptor linked list
    uint16_t num_free_      = 0;    // Number of free descriptors remaining
    uint16_t last_used_idx_ = 0;    // Last used ring index we processed
    uint64_t io_base_       = 0;    // Device base (I/O port on x86, MMIO on ARM64)
    uint16_t queue_index_   = 0;    // This queue's index (for notify)
    bool     is_mmio_       = false; // true = virtio-mmio transport
    bool*    desc_used_     = nullptr; // Tracks which descriptors are in use
};

// ============================================================================
// Free functions for legacy virtio PCI transport
// ============================================================================

// Read BAR0 from a PCI device and return the base address.
// On x86_64: returns an I/O port number (BAR0 I/O space, 16-bit).
// On aarch64: returns an MMIO address (BAR0 memory space, 64-bit).
uint64_t find_base_addr(const pci::Device& dev);

// Set the device status register.
void set_status(uint64_t base, uint8_t status);

// Read the device status register.
uint8_t get_status(uint64_t base);

// Reset the device by writing 0 to the status register.
void reset(uint64_t base);

// Read the device feature bits.
uint32_t read_device_features(uint64_t base);

// Write the guest (driver) feature bits.
void write_guest_features(uint64_t base, uint32_t features);

} // namespace virtio
