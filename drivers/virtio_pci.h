#pragma once
// drivers/virtio_pci.h — Modern VirtIO PCI transport (VirtIO 1.0+)
//
// Discovers and initializes virtio devices on the PCI bus using the modern
// transport, which locates config structures via PCI vendor-specific
// capabilities (cap_vndr=0x09).  Required for Apple VZ.framework which
// exposes all I/O as virtio-pci (modern only, no transitional devices).
//
// Device IDs: vendor 0x1AF4, device 0x1040+type (net=0x1041, console=0x1043).

#include "drivers/pci.h"
#include <stdint.h>

namespace virtio_pci {

// Maximum number of virtio-pci devices we can track
static constexpr int MAX_DEVICES = 8;

struct Device {
  pci::Device *pci_dev;
  volatile uint8_t *common_cfg;  // VIRTIO_PCI_CAP_COMMON_CFG
  volatile uint8_t *notify_base; // VIRTIO_PCI_CAP_NOTIFY_CFG
  volatile uint8_t *device_cfg;  // VIRTIO_PCI_CAP_DEVICE_CFG
  uint32_t notify_off_multiplier;
  uint16_t virtio_device_type; // 1=net, 3=console, etc.
};

// Discover a modern virtio-pci device by virtio device type (1=net, 3=console).
// Searches for vendor=0x1AF4, device_id=0x1040+type.
// Parses PCI capability list to locate common_cfg, notify, device_cfg.
// Returns nullptr if not found.
Device *find(uint16_t virtio_device_type);

// ---- Transport operations via common_cfg -----------------------------------

void reset(Device *dev);
void set_status(Device *dev, uint8_t status);
uint8_t get_status(Device *dev);

// Read device features (word 0 = bits 0-31, word 1 = bits 32-63)
uint32_t read_features(Device *dev, uint32_t word);
void write_features(Device *dev, uint32_t word, uint32_t features);

// ---- Queue operations via common_cfg ---------------------------------------

void select_queue(Device *dev, uint16_t idx);
uint16_t get_queue_size(Device *dev);
void set_queue_size(Device *dev, uint16_t size);
void set_queue_addrs(Device *dev, uint64_t desc, uint64_t avail, uint64_t used);
void enable_queue(Device *dev);
uint16_t get_queue_notify_off(Device *dev);

// Compute the notify address for a queue (used by Virtqueue::kick)
uint64_t queue_notify_addr(Device *dev, uint16_t notify_off);

// ---- Device-specific config ------------------------------------------------

uint8_t read_dev_cfg8(Device *dev, uint32_t offset);
uint16_t read_dev_cfg16(Device *dev, uint32_t offset);
uint32_t read_dev_cfg32(Device *dev, uint32_t offset);

} // namespace virtio_pci
