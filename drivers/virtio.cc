// drivers/virtio.cc -- Virtio PCI transport and split virtqueue implementation
//
// Implements the legacy (0.9.5) virtio PCI transport. The split virtqueue
// consists of three physically contiguous regions:
//   1. Descriptor table  (16 bytes per entry, aligned to 16)
//   2. Available ring    (6 + 2*queue_size bytes, aligned to 2)
//   3. Used ring         (6 + 8*queue_size bytes, aligned to 4096)
//
// Memory layout:
//   Page 1+: [descriptors][available ring] -- together, page-aligned
//   Page N+: [used ring]                   -- starts at a page boundary

#include "drivers/virtio.h"
#include "kernel/arch.h"
#include "kernel/mm.h"
#include "kernel/serial.h"

namespace virtio {

// ============================================================================
// Alignment helpers
// ============================================================================

static inline uint64_t align_up(uint64_t value, uint64_t alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}

// ============================================================================
// Free functions -- legacy PCI transport register access
// ============================================================================

uint64_t find_base_addr(const pci::Device &dev) {
  uint32_t bar0 = dev.bar[0];
#if defined(__aarch64__)
  // ARM64 has no I/O port instructions.  The QEMU virt machine maps the
  // PCIe I/O window at CPU 0x3EFF0000 (DTB `ranges` 0x01000000 entry).
  // virtio-pci legacy uses an I/O BAR0; translate the assigned I/O port to
  // its corresponding MMIO address through the PCI I/O CPU window.
  static constexpr uint64_t PCI_IO_CPU_BASE = 0x3EFF0000ULL;
  if (bar0 & 0x01) {
    uint64_t io_port = (uint64_t)(bar0 & ~0x03u);
    return PCI_IO_CPU_BASE + io_port;
  }
  return (uint64_t)(bar0 & ~0x0Fu);
#else
  // x86_64: legacy virtio uses an I/O space BAR (bit 0 set).
  if (!(bar0 & 0x01)) {
    serial::printf("virtio: BAR0 is not I/O space!\n");
    return 0;
  }
  return (uint64_t)(bar0 & ~0x03u);
#endif
}

void set_status(uint64_t base, uint8_t status) {
  arch::virtio_write8(base + REG_DEVICE_STATUS, status);
}

uint8_t get_status(uint64_t base) {
  return arch::virtio_read8(base + REG_DEVICE_STATUS);
}

void reset(uint64_t base) { arch::virtio_write8(base + REG_DEVICE_STATUS, 0); }

uint32_t read_device_features(uint64_t base) {
  return arch::virtio_read32(base + REG_DEVICE_FEATURES);
}

void write_guest_features(uint64_t base, uint32_t features) {
  arch::virtio_write32(base + REG_GUEST_FEATURES, features);
}

// ============================================================================
// Virtqueue implementation
// ============================================================================

bool Virtqueue::init(uint16_t queue_size_param, uint64_t base,
                     uint16_t queue_index, bool is_mmio, bool is_mmio_v2) {
  io_base_ = base;
  queue_index_ = queue_index;
  is_mmio_ = is_mmio;

  // Step 1 & 2: Select queue and determine its size.
  // PCI transport: write 16-bit QueueSelect, read 16-bit QueueSize.
  // MMIO transport: write 32-bit QueueSel, read 32-bit QueueNumMax,
  //                 then write QueueNum and QueueAlign (4096).
  if (is_mmio_) {
    arch::virtio_write32(io_base_ + mmio::QUEUE_SEL, queue_index_);
    uint32_t qmax = arch::virtio_read32(io_base_ + mmio::QUEUE_NUM_MAX);
    if (qmax == 0) {
      serial::printf("virtio: queue %d has size 0\n", queue_index_);
      return false;
    }
    // Cap at 256 to keep memory usage reasonable
    queue_size_ = (qmax > 256) ? 256 : (uint16_t)qmax;
    arch::virtio_write32(io_base_ + mmio::QUEUE_NUM, queue_size_);
    if (!is_mmio_v2) {
      // QUEUE_ALIGN is v1-only; reserved in v2 (0x03c is undefined).
      arch::virtio_write32(io_base_ + mmio::QUEUE_ALIGN, 4096);
    }
  } else {
    arch::virtio_write16(io_base_ + REG_QUEUE_SELECT, queue_index_);
    uint16_t dev_queue_size = arch::virtio_read16(io_base_ + REG_QUEUE_SIZE);
    if (dev_queue_size == 0) {
      serial::printf("virtio: queue %d has size 0\n", queue_index_);
      return false;
    }
    queue_size_ = dev_queue_size;
  }

  serial::printf("virtio: queue %d size = %d\n", queue_index_, queue_size_);

  // Step 3: Calculate memory layout sizes
  //
  // Descriptors + available ring go into the first region, page-aligned.
  // Used ring goes into the second region, also page-aligned.
  uint64_t desc_size = (uint64_t)queue_size_ * sizeof(VirtqDesc);
  uint64_t avail_size =
      6 + 2 * (uint64_t)queue_size_; // flags + idx + ring[] + used_event
  uint64_t used_size =
      6 + 8 * (uint64_t)queue_size_; // flags + idx + ring[] + avail_event

  uint64_t first_region = align_up(desc_size + avail_size, 4096);
  uint64_t second_region = align_up(used_size, 4096);
  uint64_t total_size = first_region + second_region;

  // Step 4: Allocate physically contiguous memory
  // alloc_frame returns a physical address of a 4096-byte frame.
  // We need enough frames for the total size.
  uint64_t num_frames = (total_size + 4095) / 4096;

  // Allocate the first frame -- this is our base physical address.
  // For simplicity, we allocate consecutive frames and assume they are
  // contiguous. In a real system, you'd use a contiguous allocator.
  uint64_t phys_base = mm::alloc_frame();
  if (phys_base == 0) {
    serial::printf("virtio: failed to allocate memory for queue %d\n",
                   queue_index_);
    return false;
  }

  // Allocate remaining frames (they should be contiguous from a frame allocator
  // that hands out sequential frames).
  for (uint64_t i = 1; i < num_frames; i++) {
    mm::alloc_frame();
  }

  // In a unikernel with identity mapping, physical == virtual.
  uint8_t *base_ptr = reinterpret_cast<uint8_t *>(phys_base);

  // Step 5: Zero the entire region
  for (uint64_t i = 0; i < total_size; i++) {
    base_ptr[i] = 0;
  }

  // Step 6: Set up pointers into the memory regions
  descs_ = reinterpret_cast<VirtqDesc *>(base_ptr);
  avail_ = reinterpret_cast<VirtqAvail *>(base_ptr + desc_size);
  used_ = reinterpret_cast<VirtqUsed *>(base_ptr + first_region);

  // Step 7: Initialize the free descriptor linked list.
  // Chain all descriptors: desc[0] -> desc[1] -> ... -> desc[n-1]
  for (uint16_t i = 0; i < queue_size_; i++) {
    descs_[i].next = i + 1;
    descs_[i].flags = 0;
  }
  free_head_ = 0;
  num_free_ = queue_size_;

  // Allocate the desc_used tracking array
  desc_used_ =
      reinterpret_cast<bool *>(mm::kmalloc(queue_size_ * sizeof(bool)));
  if (desc_used_) {
    for (uint16_t i = 0; i < queue_size_; i++) {
      desc_used_[i] = false;
    }
  }

  last_used_idx_ = 0;

  // Suppress interrupts -- we poll, not interrupt-driven
  avail_->flags = VIRTQ_AVAIL_F_NO_INTERRUPT;

  // Step 8: Tell the device where the queue lives.
  // v1 MMIO / PCI: single QUEUE_PFN/REG_QUEUE_ADDRESS (phys >> 12).
  // v2 MMIO: separate addresses for desc table, available ring, used ring.
  if (is_mmio_) {
    if (is_mmio_v2) {
      uint64_t avail_phys = phys_base + desc_size;
      uint64_t used_phys = phys_base + first_region;
      arch::virtio_write32(io_base_ + mmio::QUEUE_DESC_LOW,
                           (uint32_t)phys_base);
      arch::virtio_write32(io_base_ + mmio::QUEUE_DESC_HIGH,
                           (uint32_t)(phys_base >> 32));
      arch::virtio_write32(io_base_ + mmio::QUEUE_DRIVER_LOW,
                           (uint32_t)avail_phys);
      arch::virtio_write32(io_base_ + mmio::QUEUE_DRIVER_HIGH,
                           (uint32_t)(avail_phys >> 32));
      arch::virtio_write32(io_base_ + mmio::QUEUE_DEVICE_LOW,
                           (uint32_t)used_phys);
      arch::virtio_write32(io_base_ + mmio::QUEUE_DEVICE_HIGH,
                           (uint32_t)(used_phys >> 32));
      arch::virtio_write32(io_base_ + mmio::QUEUE_READY, 1);
    } else {
      arch::virtio_write32(io_base_ + mmio::QUEUE_PFN,
                           (uint32_t)(phys_base >> 12));
    }
  } else {
    arch::virtio_write32(io_base_ + REG_QUEUE_ADDRESS,
                         (uint32_t)(phys_base >> 12));
  }

  serial::printf("virtio: queue %d initialized at phys 0x%lx\n", queue_index_,
                 phys_base);
  return true;
}

bool Virtqueue::init_pci_modern(uint16_t queue_size_param, uint64_t notify_addr,
                                uint16_t queue_index, uint64_t *desc_phys,
                                uint64_t *avail_phys, uint64_t *used_phys) {
  queue_index_ = queue_index;
  notify_addr_ = notify_addr;
  is_mmio_ = false;
  queue_size_ = queue_size_param;

  if (queue_size_ == 0) {
    serial::printf("virtio: queue %d has size 0\n", queue_index_);
    return false;
  }

  serial::printf("virtio: queue %d size = %d (PCI modern)\n", queue_index_,
                 queue_size_);

  // Calculate memory layout sizes (same as legacy init)
  uint64_t desc_size = (uint64_t)queue_size_ * sizeof(VirtqDesc);
  uint64_t avail_size = 6 + 2 * (uint64_t)queue_size_;
  uint64_t used_size = 6 + 8 * (uint64_t)queue_size_;

  // Modern virtio: desc aligned to 16, avail to 2, used to 4.
  // We still page-align for simplicity with frame allocator.
  uint64_t first_region = align_up(desc_size + avail_size, 4096);
  uint64_t second_region = align_up(used_size, 4096);
  uint64_t total_size = first_region + second_region;

  uint64_t num_frames = (total_size + 4095) / 4096;
  uint64_t phys_base = mm::alloc_frame();
  if (phys_base == 0) {
    serial::printf("virtio: failed to allocate memory for queue %d\n",
                   queue_index_);
    return false;
  }
  for (uint64_t i = 1; i < num_frames; i++) {
    mm::alloc_frame();
  }

  uint8_t *base_ptr = reinterpret_cast<uint8_t *>(phys_base);
  for (uint64_t i = 0; i < total_size; i++) {
    base_ptr[i] = 0;
  }

  descs_ = reinterpret_cast<VirtqDesc *>(base_ptr);
  avail_ = reinterpret_cast<VirtqAvail *>(base_ptr + desc_size);
  used_ = reinterpret_cast<VirtqUsed *>(base_ptr + first_region);

  for (uint16_t i = 0; i < queue_size_; i++) {
    descs_[i].next = i + 1;
    descs_[i].flags = 0;
  }
  free_head_ = 0;
  num_free_ = queue_size_;

  desc_used_ =
      reinterpret_cast<bool *>(mm::kmalloc(queue_size_ * sizeof(bool)));
  if (desc_used_) {
    for (uint16_t i = 0; i < queue_size_; i++) {
      desc_used_[i] = false;
    }
  }

  last_used_idx_ = 0;
  avail_->flags = VIRTQ_AVAIL_F_NO_INTERRUPT;

  // Return physical addresses for caller to pass to virtio_pci::set_queue_addrs
  *desc_phys = phys_base;
  *avail_phys = phys_base + desc_size;
  *used_phys = phys_base + first_region;

  serial::printf("virtio: queue %d initialized at phys 0x%lx (PCI modern)\n",
                 queue_index_, phys_base);
  return true;
}

int Virtqueue::add_buf(void **buffers, uint32_t *lengths, int out_count,
                       int in_count) {
  int total = out_count + in_count;
  if (total == 0) {
    return -1;
  }
  if (num_free_ < (uint16_t)total) {
    serial::printf("virtio: queue %d: not enough free descriptors "
                   "(%d needed, %d free)\n",
                   queue_index_, total, num_free_);
    return -1;
  }

  // Remember the head of this descriptor chain
  uint16_t head = free_head_;
  uint16_t idx = head;

  // Set up output (device-readable) buffers
  for (int i = 0; i < out_count; i++) {
    descs_[idx].addr = reinterpret_cast<uint64_t>(buffers[i]);
    descs_[idx].len = lengths[i];
    descs_[idx].flags = 0;
    if (i < total - 1) {
      descs_[idx].flags |= VIRTQ_DESC_F_NEXT;
    }
    if (desc_used_)
      desc_used_[idx] = true;
    idx = descs_[idx].next;
  }

  // Set up input (device-writable) buffers
  for (int i = 0; i < in_count; i++) {
    descs_[idx].addr = reinterpret_cast<uint64_t>(buffers[out_count + i]);
    descs_[idx].len = lengths[out_count + i];
    descs_[idx].flags = VIRTQ_DESC_F_WRITE;
    if (i < in_count - 1) {
      descs_[idx].flags |= VIRTQ_DESC_F_NEXT;
    }
    if (desc_used_)
      desc_used_[idx] = true;
    idx = descs_[idx].next;
  }

  // Advance the free list head past the descriptors we just consumed
  free_head_ = idx;
  num_free_ -= (uint16_t)total;

  // Add the chain head to the available ring
  uint16_t avail_idx = avail_->idx & (queue_size_ - 1);
  avail_->ring[avail_idx] = head;

  // Store barrier: descriptor fields must be visible to the device before
  // avail_->idx is updated.  On x86 TSO a compiler barrier suffices, but
  // ARM64's weak memory model requires DSB ST.
  arch::dsb_st();

  avail_->idx++;

  return (int)head;
}

void Virtqueue::kick() {
  // Store barrier: avail_->idx must be visible before the doorbell write.
  arch::dsb_st();
  if (notify_addr_ != 0) {
    // Modern PCI: write queue_index to the notify MMIO address
    *reinterpret_cast<volatile uint16_t *>(notify_addr_) = queue_index_;
  } else if (is_mmio_) {
    arch::virtio_write32(io_base_ + mmio::QUEUE_NOTIFY, queue_index_);
  } else {
    arch::virtio_write16(io_base_ + REG_QUEUE_NOTIFY, queue_index_);
  }
}

bool Virtqueue::get_used(uint16_t *id, uint32_t *len) {
  // Load barrier: ensures we see the device's latest writes to used_->idx
  // and used_->ring[] before reading them.  Required on ARM64's weak model.
  arch::dsb_ld();

  if (last_used_idx_ == used_->idx) {
    return false; // No new used entries
  }

  // Read the next used element
  uint16_t used_slot = last_used_idx_ & (queue_size_ - 1);
  *id = (uint16_t)used_->ring[used_slot].id;
  *len = used_->ring[used_slot].len;

  last_used_idx_++;

  // Return all descriptors in this chain to the free list.
  uint16_t idx = *id;
  while (true) {
    if (desc_used_)
      desc_used_[idx] = false;
    num_free_++;

    if (!(descs_[idx].flags & VIRTQ_DESC_F_NEXT)) {
      // End of chain: link this descriptor to current free_head
      descs_[idx].next = free_head_;
      free_head_ = *id; // Prepend the whole chain
      break;
    }
    idx = descs_[idx].next;
  }

  return true;
}

} // namespace virtio
