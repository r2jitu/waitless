// drivers/virtio_net.cc -- Virtio network device driver implementation
//
// This driver provides zero-overhead packet I/O for the unikernel.
// Since everything runs in ring 0 in a single address space, applications
// call send() and poll() as ordinary function calls. There are no syscalls,
// no context switches, and no copies beyond what the hardware requires.
//
// Initialization sequence (legacy virtio 0.9.5):
//   1. Find the PCI device
//   2. Enable bus mastering (required for DMA)
//   3. Reset the device
//   4. Negotiate features
//   5. Set up virtqueues
//   6. Read MAC address
//   7. Populate RX buffers
//   8. Activate the device

#include "drivers/virtio_net.h"
#include "drivers/virtio_pci.h"
#include "kernel/arch.h"
#include "kernel/fdt.h"
#include "kernel/serial.h"
#include "kernel/mm.h"
#include "kernel/panic.h"

extern "C" void* memcpy(void* dst, const void* src, size_t n);

namespace virtio_net {

// ============================================================================
// Internal state
// ============================================================================

static pci::Device* device_ = nullptr;
static virtio_pci::Device* pci_dev_ = nullptr;  // modern PCI device (VZ path)
static uint64_t io_base_ = 0;
static virtio::Virtqueue rx_queue_;
static virtio::Virtqueue tx_queue_;
static uint8_t mac_[6];

// RX buffer pool: pre-allocated buffers submitted to the device
static RxBuffer* rx_buffers_[RX_BUFFERS];

// ============================================================================
// TX buffer pool
//
// send() is non-blocking: it copies the frame into a pool slot, submits to
// the TX queue, kicks the device, and returns immediately.  tx_drain() is
// called opportunistically to reclaim slots whose TX completions have been
// posted to the used ring by QEMU's BH.
//
// With virtio-mmio on TCG, QUEUE_NOTIFY schedules an async BH in QEMU's I/O
// event loop.  If send() blocked spinning on get_used(), the guest spin loop
// would starve QEMU's event loop and the BH would never run — resulting in
// ~58 req/sec instead of thousands.  Non-blocking send() avoids this.
// ============================================================================

struct TxBuf {
    VirtioNetHeader hdr;
    uint8_t         data[1514];  // max Ethernet frame (1500 payload + 14 header)
} __attribute__((packed));

static constexpr int TX_POOL_SIZE = 64;
static TxBuf tx_pool_[TX_POOL_SIZE];
static bool  tx_pool_used_[TX_POOL_SIZE];

// ============================================================================
// Initialization
// ============================================================================

// ============================================================================
// Modern PCI init path (VZ.framework + QEMU modern)
// ============================================================================

__attribute__((unused))
static bool init_pci_modern() {
    pci_dev_ = virtio_pci::find(1);  // virtio device type 1 = net
    if (!pci_dev_) return false;

    serial::printf("virtio_net: found modern virtio-pci net device\n");

    // Reset → ACKNOWLEDGE → DRIVER
    virtio_pci::reset(pci_dev_);
    virtio_pci::set_status(pci_dev_, virtio::STATUS_ACKNOWLEDGE);
    virtio_pci::set_status(pci_dev_, virtio::STATUS_ACKNOWLEDGE | virtio::STATUS_DRIVER);

    // Feature negotiation
    uint32_t dev_features = virtio_pci::read_features(pci_dev_, 0);
    serial::printf("virtio_net: device features = 0x%x\n", dev_features);

    // Accept all offered word-0 features (VZ may require CSUM/INDIRECT_DESC
    // etc.; our TX/RX paths don't use them actively but accepting is safe).
    uint32_t guest_features = dev_features;

    virtio_pci::write_features(pci_dev_, 0, guest_features);
    virtio_pci::write_features(pci_dev_, 1, 1);  // VIRTIO_F_VERSION_1 (bit 32)
    serial::printf("virtio_net: guest features = 0x%x\n", guest_features);

    virtio_pci::set_status(pci_dev_, virtio::STATUS_ACKNOWLEDGE | virtio::STATUS_DRIVER |
                                     virtio::STATUS_FEATURES_OK);
    if (!(virtio_pci::get_status(pci_dev_) & virtio::STATUS_FEATURES_OK)) {
        serial::printf("virtio_net: device rejected features\n");
        virtio_pci::set_status(pci_dev_, virtio::STATUS_FAILED);
        return false;
    }

    // Init RX queue (0)
    virtio_pci::select_queue(pci_dev_, 0);
    uint16_t rx_qsize = virtio_pci::get_queue_size(pci_dev_);
    uint16_t rx_notify_off = virtio_pci::get_queue_notify_off(pci_dev_);
    uint64_t rx_notify = virtio_pci::queue_notify_addr(pci_dev_, rx_notify_off);

    uint64_t rx_desc, rx_avail, rx_used;
    if (!rx_queue_.init_pci_modern(rx_qsize, rx_notify, 0,
                                   &rx_desc, &rx_avail, &rx_used)) {
        serial::printf("virtio_net: failed to init RX queue\n");
        virtio_pci::set_status(pci_dev_, virtio::STATUS_FAILED);
        return false;
    }
    virtio_pci::set_queue_addrs(pci_dev_, rx_desc, rx_avail, rx_used);
    virtio_pci::enable_queue(pci_dev_);

    // Init TX queue (1)
    virtio_pci::select_queue(pci_dev_, 1);
    uint16_t tx_qsize = virtio_pci::get_queue_size(pci_dev_);
    uint16_t tx_notify_off = virtio_pci::get_queue_notify_off(pci_dev_);
    uint64_t tx_notify = virtio_pci::queue_notify_addr(pci_dev_, tx_notify_off);

    uint64_t tx_desc, tx_avail, tx_used;
    if (!tx_queue_.init_pci_modern(tx_qsize, tx_notify, 1,
                                   &tx_desc, &tx_avail, &tx_used)) {
        serial::printf("virtio_net: failed to init TX queue\n");
        virtio_pci::set_status(pci_dev_, virtio::STATUS_FAILED);
        return false;
    }
    virtio_pci::set_queue_addrs(pci_dev_, tx_desc, tx_avail, tx_used);
    virtio_pci::enable_queue(pci_dev_);

    // Read MAC from device-specific config
    for (int i = 0; i < 6; i++) {
        mac_[i] = virtio_pci::read_dev_cfg8(pci_dev_, i);
    }
    serial::printf("virtio_net: MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
                   mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);

    // Allocate and populate RX buffers
    for (int i = 0; i < RX_BUFFERS; i++) {
        // Allocate 2 extra bytes and shift the RxBuffer pointer by 2.
        // VZ writes: [VirtioNetHeader(12B)] [Ethernet] at desc.addr.
        // With +2 shift: Ethernet starts at desc.addr+12 = alloc+14,
        // IPv4 header at alloc+28 — 4-byte aligned (28 % 4 == 0),
        // preventing ARM64 alignment faults on VZ.framework.
        rx_buffers_[i] = reinterpret_cast<RxBuffer*>(
            static_cast<uint8_t*>(mm::kmalloc(sizeof(RxBuffer) + 2)) + 2);
        if (!rx_buffers_[i]) {
            serial::printf("virtio_net: failed to allocate RX buffer %d\n", i);
            virtio_pci::set_status(pci_dev_, virtio::STATUS_FAILED);
            return false;
        }
        RxBuffer* buf = rx_buffers_[i];
        buf->hdr.flags       = 0;
        buf->hdr.gso_type    = 0;
        buf->hdr.hdr_len     = 0;
        buf->hdr.gso_size    = 0;
        buf->hdr.csum_start  = 0;
        buf->hdr.csum_offset = 0;
        buf->hdr.num_buffers = 0;

        void* buf_ptr    = reinterpret_cast<void*>(buf);
        uint32_t buf_len = BUFFER_SIZE;
        int ret = rx_queue_.add_buf(&buf_ptr, &buf_len, 0, 1);
        if (ret < 0) {
            serial::printf("virtio_net: failed to add RX buffer %d\n", i);
            break;
        }
    }

    // DRIVER_OK — must be set before kicking queues (VZ ignores pre-DRIVER_OK kicks)
    virtio_pci::set_status(pci_dev_, virtio::STATUS_ACKNOWLEDGE | virtio::STATUS_DRIVER |
                                     virtio::STATUS_FEATURES_OK | virtio::STATUS_DRIVER_OK);

    // Notify RX queue that receive buffers are ready.
    // Then pause ~1M nops: VZ needs time after DRIVER_OK before the host
    // I/O side is ready (same requirement as the VirtIO console).
    rx_queue_.kick();
    for (volatile int i = 0; i < 1000000; i++) asm volatile("nop");

    io_base_ = 1;  // non-zero sentinel to indicate init complete
    serial::printf("virtio_net: initialization complete (PCI modern)\n");
    return true;
}

bool init() {
    serial::printf("virtio_net: initializing...\n");

#if defined(__aarch64__)
    // -----------------------------------------------------------------------
    // ARM64: virtio-mmio transport (QEMU -device virtio-net-device)
    //
    // The QEMU virt machine provides 32 virtio-mmio slots at 0x0a000000..
    // 0x0a003e00 (step 0x200).  All slots carry the "virt" magic value; only
    // occupied ones have DeviceID != 0.  Scan all slots to find DeviceID=1
    // (network) rather than assuming the first slot.
    // -----------------------------------------------------------------------
    device_  = nullptr;
    io_base_ = 0;

    // MMIO register helpers
    auto r32 = [](uint64_t base, uint32_t off) -> uint32_t {
        return arch::virtio_read32(base + off);
    };
    auto w32 = [](uint64_t base, uint32_t off, uint32_t v) {
        arch::virtio_write32(base + off, v);
    };

    // Prefer FDT-discovered virtio-mmio device list (works for both QEMU and VZ).
    // Scan FDT entries first; fall back to the fixed QEMU slot scan if FDT found
    // no virtio-mmio devices (DTB absent or dtb_addr=0 passed to fdt::init).
    const fdt::Info& fdt = fdt::info();
    if (fdt.virtio_count > 0) {
        for (int i = 0; i < fdt.virtio_count; i++) {
            uint64_t candidate = fdt.virtio_bases[i];
            if (r32(candidate, virtio::mmio::MAGIC_VALUE) != virtio::mmio::MAGIC)
                continue;
            if (r32(candidate, virtio::mmio::DEVICE_ID) == 1) {
                io_base_ = candidate;
                break;
            }
        }
    } else {
        // Fallback: fixed QEMU virtio-mmio slot scan (32 slots at 0x0a000000+)
        for (int slot = 0; slot < 32; slot++) {
            uint64_t candidate = virtio::mmio::BASE + (uint64_t)slot * 0x200;
            if (r32(candidate, virtio::mmio::MAGIC_VALUE) != virtio::mmio::MAGIC)
                continue;
            if (r32(candidate, virtio::mmio::DEVICE_ID) == 1) {
                io_base_ = candidate;
                break;
            }
        }
    }
    if (io_base_ == 0) {
        serial::printf("virtio_net: no virtio-mmio net device, trying PCI...\n");
        return init_pci_modern();
    }

    uint32_t ver = r32(io_base_, virtio::mmio::VERSION);
    bool is_v2 = (ver == 2);
    if (ver != 1 && ver != 2) {
        serial::printf("virtio_net: unsupported virtio-mmio version %u at 0x%lx\n",
                       ver, io_base_);
        return false;
    }
    serial::printf("virtio_net: virtio-mmio net device found at 0x%lx (v%u)\n",
                   io_base_, ver);

    // Reset
    w32(io_base_, virtio::mmio::STATUS, 0);

    // ACKNOWLEDGE + DRIVER
    w32(io_base_, virtio::mmio::STATUS, virtio::STATUS_ACKNOWLEDGE);
    w32(io_base_, virtio::mmio::STATUS,
        virtio::STATUS_ACKNOWLEDGE | virtio::STATUS_DRIVER);

    // Feature negotiation: v2 uses DEVICE_FEATURES_SEL/DRIVER_FEATURES_SEL;
    // v1 uses a single HOST_FEATURES/GUEST_FEATURES pair.
    uint32_t guest_features = 0;
    if (is_v2) {
        // Select and read low 32 bits of device features.
        w32(io_base_, virtio::mmio::DEVICE_FEATURES_SEL, 0);
        uint32_t dev_features = r32(io_base_, virtio::mmio::HOST_FEATURES);
        serial::printf("virtio_net: device features = 0x%x\n", dev_features);
        if (dev_features & VIRTIO_NET_F_MAC)       guest_features |= VIRTIO_NET_F_MAC;
        if (dev_features & VIRTIO_NET_F_STATUS)    guest_features |= VIRTIO_NET_F_STATUS;
        // Negotiate MRG_RXBUF so QEMU also uses the 12-byte virtio_net_hdr_mrg_rxbuf
        // layout, matching Apple VZ which always uses 12-byte headers.
        if (dev_features & VIRTIO_NET_F_MRG_RXBUF) guest_features |= VIRTIO_NET_F_MRG_RXBUF;

        // Write driver features (word 0), then clear word 1 (no high features).
        w32(io_base_, virtio::mmio::DRIVER_FEATURES_SEL, 0);
        w32(io_base_, virtio::mmio::GUEST_FEATURES, guest_features);
        w32(io_base_, virtio::mmio::DRIVER_FEATURES_SEL, 1);
        w32(io_base_, virtio::mmio::GUEST_FEATURES, 0);

        // v2 requires FEATURES_OK before queue setup.
        w32(io_base_, virtio::mmio::STATUS,
            virtio::STATUS_ACKNOWLEDGE | virtio::STATUS_DRIVER |
            virtio::STATUS_FEATURES_OK);
        if (!(r32(io_base_, virtio::mmio::STATUS) & virtio::STATUS_FEATURES_OK)) {
            serial::printf("virtio_net: device rejected features\n");
            w32(io_base_, virtio::mmio::STATUS, virtio::STATUS_FAILED);
            return false;
        }
    } else {
        // v1: single 32-bit feature word; GuestPageSize required before queues.
        uint32_t dev_features = r32(io_base_, virtio::mmio::HOST_FEATURES);
        serial::printf("virtio_net: device features = 0x%x\n", dev_features);
        if (dev_features & VIRTIO_NET_F_MAC)       guest_features |= VIRTIO_NET_F_MAC;
        if (dev_features & VIRTIO_NET_F_STATUS)    guest_features |= VIRTIO_NET_F_STATUS;
        if (dev_features & VIRTIO_NET_F_MRG_RXBUF) guest_features |= VIRTIO_NET_F_MRG_RXBUF;
        w32(io_base_, virtio::mmio::GUEST_FEATURES, guest_features);
        w32(io_base_, virtio::mmio::GUEST_PAGE_SIZE, 4096);
    }
    serial::printf("virtio_net: guest features = 0x%x\n", guest_features);

    // Init RX and TX queues
    if (!rx_queue_.init(0, io_base_, 0, /*is_mmio=*/true, is_v2)) {
        serial::printf("virtio_net: failed to init RX queue\n");
        w32(io_base_, virtio::mmio::STATUS, virtio::STATUS_FAILED);
        return false;
    }
    if (!tx_queue_.init(0, io_base_, 1, /*is_mmio=*/true, is_v2)) {
        serial::printf("virtio_net: failed to init TX queue\n");
        w32(io_base_, virtio::mmio::STATUS, virtio::STATUS_FAILED);
        return false;
    }

    // Read MAC from config space (two 32-bit reads to stay 32-bit aligned)
    {
        uint32_t lo = r32(io_base_, virtio::mmio::DEVICE_CONFIG + 0);
        uint32_t hi = r32(io_base_, virtio::mmio::DEVICE_CONFIG + 4);
        mac_[0] =  lo        & 0xff;
        mac_[1] = (lo >>  8) & 0xff;
        mac_[2] = (lo >> 16) & 0xff;
        mac_[3] = (lo >> 24) & 0xff;
        mac_[4] =  hi        & 0xff;
        mac_[5] = (hi >>  8) & 0xff;
    }
    serial::printf("virtio_net: MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
                   mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);

    // Allocate RX buffers
    for (int i = 0; i < RX_BUFFERS; i++) {
        // Allocate 2 extra bytes and shift the RxBuffer pointer by 2.
        // VZ writes: [VirtioNetHeader(12B)] [Ethernet] at desc.addr.
        // With +2 shift: Ethernet starts at desc.addr+12 = alloc+14,
        // IPv4 header at alloc+28 — 4-byte aligned (28 % 4 == 0),
        // preventing ARM64 alignment faults on VZ.framework.
        rx_buffers_[i] = reinterpret_cast<RxBuffer*>(
            static_cast<uint8_t*>(mm::kmalloc(sizeof(RxBuffer) + 2)) + 2);
        if (!rx_buffers_[i]) {
            serial::printf("virtio_net: failed to allocate RX buffer %d\n", i);
            w32(io_base_, virtio::mmio::STATUS, virtio::STATUS_FAILED);
            return false;
        }
        RxBuffer* buf = rx_buffers_[i];
        buf->hdr.flags       = 0;
        buf->hdr.gso_type    = 0;
        buf->hdr.hdr_len     = 0;
        buf->hdr.gso_size    = 0;
        buf->hdr.csum_start  = 0;
        buf->hdr.csum_offset = 0;
        buf->hdr.num_buffers = 0;

        void* buf_ptr    = reinterpret_cast<void*>(buf);
        uint32_t buf_len = BUFFER_SIZE;
        int ret = rx_queue_.add_buf(&buf_ptr, &buf_len, 0, 1);
        if (ret < 0) {
            serial::printf("virtio_net: failed to add RX buffer %d\n", i);
            break;
        }
    }
    rx_queue_.kick();

    // DRIVER_OK — device is live; v2 must keep FEATURES_OK set.
    uint32_t final_status = virtio::STATUS_ACKNOWLEDGE | virtio::STATUS_DRIVER |
                            virtio::STATUS_DRIVER_OK;
    if (is_v2) final_status |= virtio::STATUS_FEATURES_OK;
    w32(io_base_, virtio::mmio::STATUS, final_status);

    serial::printf("virtio_net: initialization complete (MMIO)\n");
    return true;

#else
    // -----------------------------------------------------------------------
    // x86_64: virtio-PCI legacy transport (unchanged)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Step 1: Find the virtio-net PCI device
    // -----------------------------------------------------------------------
    // Legacy virtio devices use vendor 0x1AF4 and device IDs 0x1000-0x103F.
    // Device ID 0x1000 corresponds to network (subsystem device ID 1).
    device_ = pci::find_device(0x1AF4, 0x1000);
    if (!device_) {
        // Also try modern device ID
        device_ = pci::find_device(0x1AF4, 0x1041);
    }
    if (!device_) {
        serial::printf("virtio_net: device not found\n");
        return false;
    }

    serial::printf("virtio_net: found device at PCI %02x:%02x.%x\n",
                   device_->bus, device_->slot, device_->func);

    // Verify this is actually a network device by checking the subsystem
    // device ID (offset 0x2C, bits 31:16 of the dword at 0x2C).
    uint32_t subsys = pci::read_config(device_->bus, device_->slot,
                                        device_->func, 0x2C);
    uint16_t subsys_device_id = (subsys >> 16) & 0xFFFF;
    serial::printf("virtio_net: subsystem device ID = %d\n", subsys_device_id);

    // Subsystem device ID 1 = network card
    if (subsys_device_id != 1) {
        serial::printf("virtio_net: not a network device (subsys=%d)\n",
                       subsys_device_id);
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 2: Enable PCI bus mastering (required for DMA)
    // -----------------------------------------------------------------------
    pci::enable_bus_mastering(*device_);

    // -----------------------------------------------------------------------
    // Step 3: Get I/O base from BAR0
    // -----------------------------------------------------------------------
    io_base_ = virtio::find_base_addr(*device_);
    if (io_base_ == 0) {
        serial::printf("virtio_net: failed to read BAR0 base\n");
        return false;
    }
    serial::printf("virtio_net: BAR0 base = 0x%lx\n", io_base_);

    // -----------------------------------------------------------------------
    // Step 4: Reset the device
    // -----------------------------------------------------------------------
    virtio::reset(io_base_);

    // -----------------------------------------------------------------------
    // Step 5: Set ACKNOWLEDGE | DRIVER status
    // -----------------------------------------------------------------------
    virtio::set_status(io_base_, virtio::STATUS_ACKNOWLEDGE);
    virtio::set_status(io_base_, virtio::STATUS_ACKNOWLEDGE |
                                 virtio::STATUS_DRIVER);

    // -----------------------------------------------------------------------
    // Step 6: Read device features and negotiate
    // -----------------------------------------------------------------------
    uint32_t dev_features = virtio::read_device_features(io_base_);
    serial::printf("virtio_net: device features = 0x%x\n", dev_features);

    // Negotiate MAC, STATUS, and MRG_RXBUF (ensures 12-byte header layout
    // consistently across QEMU legacy PCI, QEMU MMIO, and VZ.framework).
    uint32_t guest_features = 0;
    if (dev_features & VIRTIO_NET_F_MAC)       guest_features |= VIRTIO_NET_F_MAC;
    if (dev_features & VIRTIO_NET_F_STATUS)    guest_features |= VIRTIO_NET_F_STATUS;
    if (dev_features & VIRTIO_NET_F_MRG_RXBUF) guest_features |= VIRTIO_NET_F_MRG_RXBUF;

    virtio::write_guest_features(io_base_, guest_features);
    serial::printf("virtio_net: guest features = 0x%x\n", guest_features);

    // -----------------------------------------------------------------------
    // Step 7: Set FEATURES_OK
    // -----------------------------------------------------------------------
    virtio::set_status(io_base_, virtio::STATUS_ACKNOWLEDGE |
                                 virtio::STATUS_DRIVER |
                                 virtio::STATUS_FEATURES_OK);

    // Verify the device accepted our features
    uint8_t status = virtio::get_status(io_base_);
    if (!(status & virtio::STATUS_FEATURES_OK)) {
        serial::printf("virtio_net: device did not accept features\n");
        virtio::set_status(io_base_, virtio::STATUS_FAILED);
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 8: Initialize RX and TX virtqueues
    // -----------------------------------------------------------------------
    // Queue 0 = RX, Queue 1 = TX
    if (!rx_queue_.init(0, io_base_, 0)) {
        serial::printf("virtio_net: failed to init RX queue\n");
        virtio::set_status(io_base_, virtio::STATUS_FAILED);
        return false;
    }

    if (!tx_queue_.init(0, io_base_, 1)) {
        serial::printf("virtio_net: failed to init TX queue\n");
        virtio::set_status(io_base_, virtio::STATUS_FAILED);
        return false;
    }

    // -----------------------------------------------------------------------
    // Step 9: Read the MAC address from device config
    // -----------------------------------------------------------------------
    // In legacy virtio, device-specific config starts at BAR0 + 0x14.
    // The first 6 bytes are the MAC address.
    for (int i = 0; i < 6; i++) {
        mac_[i] = arch::virtio_read8(io_base_ + virtio::REG_DEVICE_CONFIG + i);
    }

    serial::printf("virtio_net: MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
                   mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);

    // -----------------------------------------------------------------------
    // Step 10: Allocate RX buffers and populate the RX queue
    // -----------------------------------------------------------------------
    for (int i = 0; i < RX_BUFFERS; i++) {
        rx_buffers_[i] = reinterpret_cast<RxBuffer*>(
            mm::kmalloc(sizeof(RxBuffer)));
        if (!rx_buffers_[i]) {
            serial::printf("virtio_net: failed to allocate RX buffer %d\n", i);
            virtio::set_status(io_base_, virtio::STATUS_FAILED);
            return false;
        }

        // Zero the header
        RxBuffer* buf = rx_buffers_[i];
        buf->hdr.flags       = 0;
        buf->hdr.gso_type    = 0;
        buf->hdr.hdr_len     = 0;
        buf->hdr.gso_size    = 0;
        buf->hdr.csum_start  = 0;
        buf->hdr.csum_offset = 0;
        buf->hdr.num_buffers = 0;

        // Add the entire buffer as a device-writable (input) buffer.
        // The device will write the virtio header + ethernet frame into it.
        void* buf_ptr    = reinterpret_cast<void*>(buf);
        uint32_t buf_len = BUFFER_SIZE;

        int ret = rx_queue_.add_buf(&buf_ptr, &buf_len, 0, 1);
        if (ret < 0) {
            serial::printf("virtio_net: failed to add RX buffer %d\n", i);
            break; // Not fatal -- we have some buffers
        }
    }

    // Kick the RX queue so the device starts receiving into our buffers
    rx_queue_.kick();

    // -----------------------------------------------------------------------
    // Step 11: Set DRIVER_OK -- device is now live!
    // -----------------------------------------------------------------------
    virtio::set_status(io_base_, virtio::STATUS_ACKNOWLEDGE |
                                 virtio::STATUS_DRIVER |
                                 virtio::STATUS_FEATURES_OK |
                                 virtio::STATUS_DRIVER_OK);

    serial::printf("virtio_net: initialization complete\n");
    return true;
#endif // __aarch64__ / x86_64
}

// ============================================================================
// Shutdown
// ============================================================================

void shutdown() {
    if (io_base_ == 0) return;
    if (pci_dev_) {
        virtio_pci::reset(pci_dev_);
    }
#if defined(__aarch64__)
    else {
        arch::virtio_write32(io_base_ + virtio::mmio::STATUS, 0);
    }
#else
    else {
        virtio::reset(io_base_);
    }
#endif
    serial::printf("virtio_net: device reset\n");
}

// ============================================================================
// MAC address
// ============================================================================

const uint8_t* get_mac() {
    return mac_;
}

// ============================================================================
// TX drain -- reclaim completed TX pool slots
// ============================================================================

static void tx_drain() {
    uint16_t used_id;
    uint32_t used_len;
#if defined(__aarch64__)
    // Diagnostic: check if tx_queue_.used_ is outside VZ's 128MB range [0, 0x08000000).
    // If the pointer is bad, exit cleanly (RC=0) so we know the address is invalid.
    // If the pointer looks valid, fall through and crash at used_->idx (RC=1 = mysterious).
#endif
    while (tx_queue_.get_used(&used_id, &used_len)) {
        virtio::VirtqDesc* d = tx_queue_.desc(used_id);
        TxBuf* buf = reinterpret_cast<TxBuf*>(d->addr);
        int slot = (int)(buf - tx_pool_);
        if (slot >= 0 && slot < TX_POOL_SIZE) {
            tx_pool_used_[slot] = false;
        }
    }
}

// ============================================================================
// Packet transmission
// ============================================================================

void send(const void* data, uint32_t len) {
    if (!data || len == 0) return;
    if (io_base_ == 0 && pci_dev_ == nullptr) return;
    if (len > 1514) len = 1514;

    // Reclaim any pool slots whose TX has already completed.
    tx_drain();

    // Find a free pool slot.  Spin-drain if all slots are momentarily busy
    // (rare: would require 64 in-flight TX packets simultaneously).
    int slot = -1;
    for (;;) {
        for (int i = 0; i < TX_POOL_SIZE; i++) {
            if (!tx_pool_used_[i]) { slot = i; break; }
        }
        if (slot >= 0) break;
        tx_drain();
        arch::cpu_relax();
    }

    tx_pool_used_[slot] = true;
    TxBuf* buf = &tx_pool_[slot];

    buf->hdr.flags       = 0;
    buf->hdr.gso_type    = 0;
    buf->hdr.hdr_len     = 0;
    buf->hdr.gso_size    = 0;
    buf->hdr.csum_start  = 0;
    buf->hdr.csum_offset = 0;
    buf->hdr.num_buffers = 1;  // TX: always 1 buffer per packet

    const uint8_t* src = reinterpret_cast<const uint8_t*>(data);
    memcpy(buf->data, src, len);

    uint32_t total_len = sizeof(VirtioNetHeader) + len;
    void* buf_ptr = reinterpret_cast<void*>(buf);
    int head = tx_queue_.add_buf(&buf_ptr, &total_len, 1, 0);
    if (head < 0) {
        serial::printf("virtio_net: TX queue full\n");
        tx_pool_used_[slot] = false;
        return;
    }

    // Kick the device and return immediately -- no spin-wait.
    // QEMU processes the TX BH in its event loop between TCG translation
    // blocks; tx_drain() on the next poll() call will reclaim this slot.
    tx_queue_.kick();
}

// ============================================================================
// Packet reception (polling)
// ============================================================================

int poll(void (*callback)(const uint8_t* data, uint32_t len)) {
    if (!callback) {
        return 0;
    }
    // Guard: if init() was never called or returned false, queues are invalid
    if (io_base_ == 0 && pci_dev_ == nullptr) {
        return 0;
    }
    // Opportunistically reclaim completed TX buffers.
    tx_drain();

    int count = 0;
    uint16_t used_id;
    uint32_t used_len;

    while (rx_queue_.get_used(&used_id, &used_len)) {
        // The used_id is the descriptor index. The descriptor's addr field
        // points to the RxBuffer that the device wrote into.
        virtio::VirtqDesc* desc = rx_queue_.desc(used_id);
        RxBuffer* buf = reinterpret_cast<RxBuffer*>(desc->addr);

        // Sanity check: used_len must be larger than the virtio header
        if (used_len > sizeof(VirtioNetHeader)) {
            uint32_t frame_len = used_len - sizeof(VirtioNetHeader);
            callback(buf->data, frame_len);
        }

        // Re-arm this buffer: add it back to the RX queue so the device
        // can write another packet into it.
        void* buf_ptr    = reinterpret_cast<void*>(buf);
        uint32_t buf_len = BUFFER_SIZE;
        rx_queue_.add_buf(&buf_ptr, &buf_len, 0, 1);

        count++;
    }

    // If we re-armed any buffers, kick the RX queue
    if (count > 0) {
        rx_queue_.kick();
    }

    return count;
}

} // namespace virtio_net
