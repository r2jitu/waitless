// drivers/virtio_pci.cc — Modern VirtIO PCI transport (VirtIO 1.0+)
//
// Parses PCI vendor-specific capabilities to locate config structures in BARs.
// Required for Apple VZ.framework which only exposes modern virtio-pci devices.

#include "drivers/virtio_pci.h"
#include "kernel/arch.h"
#if defined(__aarch64__)
#include "kernel/aarch64/mmu.h"
#endif

// Forward-declare serial::printf to avoid header dep cycle (see pci.cc
// comment).
namespace serial {
void printf(const char *fmt, ...);
}

namespace virtio_pci {

// ============================================================================
// PCI capability types for VirtIO
// ============================================================================

static constexpr uint8_t PCI_CAP_ID_VNDR = 0x09;
static constexpr uint8_t PCI_CAP_ID_MSIX = 0x11;

// virtio_pci_cap cfg_type values
static constexpr uint8_t VIRTIO_PCI_CAP_COMMON_CFG = 1;
static constexpr uint8_t VIRTIO_PCI_CAP_NOTIFY_CFG = 2;
static constexpr uint8_t VIRTIO_PCI_CAP_ISR_CFG = 3;
static constexpr uint8_t VIRTIO_PCI_CAP_DEVICE_CFG = 4;

// common_cfg field offsets
static constexpr int CC_DEVICE_FEATURE_SELECT = 0x00;
static constexpr int CC_DEVICE_FEATURE = 0x04;
static constexpr int CC_DRIVER_FEATURE_SELECT = 0x08;
static constexpr int CC_DRIVER_FEATURE = 0x0c;
static constexpr int CC_DEVICE_STATUS = 0x14;
static constexpr int CC_QUEUE_SELECT = 0x16;
static constexpr int CC_QUEUE_SIZE = 0x18;
static constexpr int CC_QUEUE_ENABLE = 0x1c;
static constexpr int CC_QUEUE_NOTIFY_OFF = 0x1e;
static constexpr int CC_QUEUE_DESC_LO = 0x20;
static constexpr int CC_QUEUE_DESC_HI = 0x24;
static constexpr int CC_QUEUE_DRIVER_LO = 0x28;
static constexpr int CC_QUEUE_DRIVER_HI = 0x2c;
static constexpr int CC_QUEUE_DEVICE_LO = 0x30;
static constexpr int CC_QUEUE_DEVICE_HI = 0x34;

// ============================================================================
// MMIO helpers for config structure access
// ============================================================================

static inline uint8_t r8(volatile uint8_t *base, int off) {
  return *(volatile uint8_t *)(base + off);
}
static inline uint16_t r16(volatile uint8_t *base, int off) {
  return *(volatile uint16_t *)(base + off);
}
static inline uint32_t r32(volatile uint8_t *base, int off) {
  return *(volatile uint32_t *)(base + off);
}
static inline void w8(volatile uint8_t *base, int off, uint8_t v) {
  *(volatile uint8_t *)(base + off) = v;
}
static inline void w16(volatile uint8_t *base, int off, uint16_t v) {
  *(volatile uint16_t *)(base + off) = v;
}
static inline void w32(volatile uint8_t *base, int off, uint32_t v) {
  *(volatile uint32_t *)(base + off) = v;
}

// ============================================================================
// Internal state
// ============================================================================

static Device devices_[MAX_DEVICES];
static int device_count_ = 0;

// ============================================================================
// BAR address resolution
// ============================================================================

// Resolve a PCI BAR to a CPU virtual address (identity-mapped).
// For 64-bit BARs above 4GB, maps the region as device memory.
static volatile uint8_t *resolve_bar(pci::Device *dev, uint8_t bar_idx) {
  uint64_t addr = pci::read_bar64(*dev, bar_idx);
  if (addr == 0)
    return nullptr;

#if defined(__aarch64__)
  // Map the BAR region if it's above 4GB (first 4GB already mapped)
  if (addr >= 0x100000000ULL) {
    // Map a generous 2MB for the BAR region
    mmu::map_device_range(addr & ~(uint64_t)0x1FFFFF, 2 << 20);
  }
#endif

  return reinterpret_cast<volatile uint8_t *>(addr);
}

// ============================================================================
// PCI capability parsing
// ============================================================================

// Parse the PCI capability list to find virtio-specific capabilities.
// Populates dev->common_cfg, dev->notify_base, dev->device_cfg.
static bool parse_capabilities(Device *dev) {
  pci::Device *pci = dev->pci_dev;

  // Check if device has capabilities (Status register bit 4)
  uint32_t status_cmd = pci::read_config(pci->bus, pci->slot, pci->func, 0x04);
  if (!((status_cmd >> 16) & (1 << 4))) {
    serial::printf("virtio_pci: device has no capabilities\n");
    return false;
  }

  // Capabilities pointer is at config offset 0x34 (low 8 bits)
  uint32_t cap_reg = pci::read_config(pci->bus, pci->slot, pci->func, 0x34);
  uint8_t cap_ptr = cap_reg & 0xFF;

  bool found_common = false, found_notify = false;

  while (cap_ptr != 0) {
    // Read capability header: [cap_vndr:8][cap_next:8][cap_len:8][cfg_type:8]
    uint32_t hdr = pci::read_config(pci->bus, pci->slot, pci->func, cap_ptr);
    uint8_t cap_vndr = hdr & 0xFF;
    uint8_t cap_next = (hdr >> 8) & 0xFF;

    if (cap_vndr == PCI_CAP_ID_MSIX && dev->msix_cap_off == 0) {
      dev->msix_cap_off = cap_ptr;
    }

    if (cap_vndr == PCI_CAP_ID_VNDR) {
      // This is a virtio-specific capability
      uint8_t cfg_type = (hdr >> 24) & 0xFF;
      // cap_len is at byte 2: (hdr >> 16) & 0xFF

      // Read bar, offset, length from the capability structure
      // struct virtio_pci_cap layout:
      //   +0: cap_vndr(8), cap_next(8), cap_len(8), cfg_type(8)
      //   +4: bar(8), id(8), padding(16)
      //   +8: offset(32)
      //   +12: length(32)
      uint32_t bar_word =
          pci::read_config(pci->bus, pci->slot, pci->func, cap_ptr + 4);
      uint8_t bar_idx = bar_word & 0xFF;
      uint32_t offset =
          pci::read_config(pci->bus, pci->slot, pci->func, cap_ptr + 8);
      // uint32_t length = pci::read_config(pci->bus, pci->slot, pci->func,
      // cap_ptr + 12);

      volatile uint8_t *bar_base = resolve_bar(pci, bar_idx);
      if (!bar_base) {
        cap_ptr = cap_next;
        continue;
      }

      switch (cfg_type) {
      case VIRTIO_PCI_CAP_COMMON_CFG:
        dev->common_cfg = bar_base + offset;
        found_common = true;
        break;
      case VIRTIO_PCI_CAP_NOTIFY_CFG:
        dev->notify_base = bar_base + offset;
        // notify_off_multiplier is at cap+16 (after the standard 16-byte cap)
        dev->notify_off_multiplier =
            pci::read_config(pci->bus, pci->slot, pci->func, cap_ptr + 16);
        found_notify = true;
        break;
      case VIRTIO_PCI_CAP_DEVICE_CFG:
        dev->device_cfg = bar_base + offset;
        break;
      case VIRTIO_PCI_CAP_ISR_CFG:
        dev->isr_cfg = bar_base + offset;
        break;
      }
    }

    cap_ptr = cap_next;
  }

  if (!found_common) {
    serial::printf("virtio_pci: missing COMMON_CFG capability\n");
    return false;
  }
  if (!found_notify) {
    serial::printf("virtio_pci: missing NOTIFY_CFG capability\n");
    return false;
  }
  // device_cfg is optional for some device types

  return true;
}

// ============================================================================
// Device discovery
// ============================================================================

Device *find(uint16_t virtio_device_type) {
  // Modern virtio-pci device ID = 0x1040 + device_type
  uint16_t target_device_id = 0x1040 + virtio_device_type;

  pci::Device *pci = pci::find_device(0x1AF4, target_device_id);
  if (!pci)
    return nullptr;

  if (device_count_ >= MAX_DEVICES)
    return nullptr;

  Device *dev = &devices_[device_count_];
  dev->pci_dev = pci;
  dev->common_cfg = nullptr;
  dev->notify_base = nullptr;
  dev->device_cfg = nullptr;
  dev->isr_cfg = nullptr;
  dev->notify_off_multiplier = 0;
  dev->virtio_device_type = virtio_device_type;
  dev->msix_table = nullptr;
  dev->msix_table_size = 0;
  dev->msix_cap_off = 0;

  // Enable bus mastering for DMA
  pci::enable_bus_mastering(*pci);

  if (!parse_capabilities(dev)) {
    return nullptr;
  }

  device_count_++;

  serial::printf("virtio_pci: found device type %d at PCI %02x:%02x.%x\n",
                 virtio_device_type, pci->bus, pci->slot, pci->func);
  return dev;
}

// ============================================================================
// Transport operations via common_cfg
// ============================================================================

void reset(Device *dev) {
  w8(dev->common_cfg, CC_DEVICE_STATUS, 0);
  // Read back to ensure the reset is complete (VirtIO spec requires this)
  while (r8(dev->common_cfg, CC_DEVICE_STATUS) != 0) {
    asm volatile("" ::: "memory");
  }
}

void set_status(Device *dev, uint8_t status) {
  w8(dev->common_cfg, CC_DEVICE_STATUS, status);
  // Apple VZ processes config-space writes asynchronously.
  // Brief delay lets the host I/O thread catch up before a subsequent read.
  for (volatile int i = 0; i < 10000; i++)
    asm volatile("nop");
}

uint8_t get_status(Device *dev) {
  return r8(dev->common_cfg, CC_DEVICE_STATUS);
}

uint32_t read_features(Device *dev, uint32_t word) {
  w32(dev->common_cfg, CC_DEVICE_FEATURE_SELECT, word);
  return r32(dev->common_cfg, CC_DEVICE_FEATURE);
}

void write_features(Device *dev, uint32_t word, uint32_t features) {
  w32(dev->common_cfg, CC_DRIVER_FEATURE_SELECT, word);
  w32(dev->common_cfg, CC_DRIVER_FEATURE, features);
  // VZ processes feature writes asynchronously; delay before next write.
  for (volatile int i = 0; i < 10000; i++)
    asm volatile("nop");
}

// ============================================================================
// Queue operations
// ============================================================================

void select_queue(Device *dev, uint16_t idx) {
  w16(dev->common_cfg, CC_QUEUE_SELECT, idx);
}

uint16_t get_queue_size(Device *dev) {
  return r16(dev->common_cfg, CC_QUEUE_SIZE);
}

void set_queue_size(Device *dev, uint16_t size) {
  w16(dev->common_cfg, CC_QUEUE_SIZE, size);
}

void set_queue_addrs(Device *dev, uint64_t desc, uint64_t avail,
                     uint64_t used) {
  w32(dev->common_cfg, CC_QUEUE_DESC_LO, (uint32_t)desc);
  w32(dev->common_cfg, CC_QUEUE_DESC_HI, (uint32_t)(desc >> 32));
  w32(dev->common_cfg, CC_QUEUE_DRIVER_LO, (uint32_t)avail);
  w32(dev->common_cfg, CC_QUEUE_DRIVER_HI, (uint32_t)(avail >> 32));
  w32(dev->common_cfg, CC_QUEUE_DEVICE_LO, (uint32_t)used);
  w32(dev->common_cfg, CC_QUEUE_DEVICE_HI, (uint32_t)(used >> 32));
}

void enable_queue(Device *dev) { w16(dev->common_cfg, CC_QUEUE_ENABLE, 1); }

uint16_t get_queue_notify_off(Device *dev) {
  return r16(dev->common_cfg, CC_QUEUE_NOTIFY_OFF);
}

uint64_t queue_notify_addr(Device *dev, uint16_t notify_off) {
  return (uint64_t)(dev->notify_base +
                    (uint64_t)notify_off * dev->notify_off_multiplier);
}

// ============================================================================
// Device-specific config
// ============================================================================

uint8_t read_dev_cfg8(Device *dev, uint32_t offset) {
  if (!dev->device_cfg)
    return 0;
  return r8(dev->device_cfg, offset);
}

uint16_t read_dev_cfg16(Device *dev, uint32_t offset) {
  if (!dev->device_cfg)
    return 0;
  return r16(dev->device_cfg, offset);
}

uint32_t read_dev_cfg32(Device *dev, uint32_t offset) {
  if (!dev->device_cfg)
    return 0;
  return r32(dev->device_cfg, offset);
}

// ============================================================================
// ISR status (read clears pending interrupt at the device)
// ============================================================================

uint8_t read_isr(Device *dev) {
  if (!dev->isr_cfg)
    return 0;
  return r8(dev->isr_cfg, 0);
}

// ============================================================================
// MSI-X support
// ============================================================================

// common_cfg offsets for MSI-X vector fields
static constexpr int CC_CONFIG_MSIX_VECTOR = 0x10;
static constexpr int CC_QUEUE_MSIX_VECTOR = 0x1a;

void set_queue_msix_vector(Device *dev, uint16_t vector) {
  w16(dev->common_cfg, CC_QUEUE_MSIX_VECTOR, vector);
}

uint16_t get_queue_msix_vector(Device *dev) {
  return r16(dev->common_cfg, CC_QUEUE_MSIX_VECTOR);
}

bool setup_msix(Device *dev, uint64_t gic_dist_base, uint32_t intid) {
  pci::Device *pci = dev->pci_dev;
  if (dev->msix_cap_off == 0)
    return false;

  // Read MSI-X Message Control via 16-bit read at cap_off + 2.
  // IMPORTANT: use 16-bit writes for Message Control — a 32-bit write
  // to cap_off clobbers read-only cap_id/cap_next and crashes VZ.
  uint16_t msg_ctrl =
      pci::read_config16(pci->bus, pci->slot, pci->func,
                         dev->msix_cap_off + 2);
  uint16_t table_size = (msg_ctrl & 0x7FF) + 1;

  // Enable MSI-X: set Enable bit (15), clear Function Mask (14).
  // Do NOT write MSI-X table entries — VZ.framework manages MSI-X routing
  // internally.  Writing GICD_SETSPI_NSR to the table crashes VZ.
  msg_ctrl |= (1 << 15);
  msg_ctrl &= ~(uint16_t)(1 << 14);
  pci::write_config16(pci->bus, pci->slot, pci->func,
                      dev->msix_cap_off + 2, msg_ctrl);

  // Set config_msix_vector to vector 0
  w16(dev->common_cfg, CC_CONFIG_MSIX_VECTOR, 0);

  dev->msix_table_size = table_size;

  serial::printf("virtio_pci: MSI-X enabled (%u vectors)\n", table_size);
  return true;
}

} // namespace virtio_pci
