// drivers/virtio_console.cc — VirtIO console driver (MMIO + PCI)
//
// Implements the virtio-console (DeviceID=3) over virtio-mmio or modern
// virtio-pci transport.  Uses two virtqueues:
//   Queue 0: receiveq  — host→guest bytes (stdin / Ctrl-C detection)
//   Queue 1: transmitq — guest→host bytes (stdout)
//
// All ring memory is statically allocated in BSS so the driver can be
// initialised before the physical memory manager (mm::init).
//
// Ring layout for each queue (QS=16, QUEUE_ALIGN=4096):
//   offset       0 : Descriptor table  — QS × 16 bytes = 256 bytes
//   offset     256 : Available ring    — 4 + QS×2 bytes = 36 bytes
//   offset    4096 : Used ring         — 4 + QS×8 bytes = 132 bytes
//   ⇒ total 8192 bytes (2 pages) per queue

#include "drivers/virtio_console.h"
#include "drivers/virtio_pci.h"
#include "kernel/arch.h"

// Virtio-mmio register offsets (from virtio.h, copied to avoid dep cycle)
namespace {

static constexpr uint32_t MMIO_MAGIC_VALUE    = 0x000;
static constexpr uint32_t MMIO_VERSION        = 0x004;
static constexpr uint32_t MMIO_DEVICE_ID      = 0x008;
static constexpr uint32_t MMIO_GUEST_FEATURES = 0x020;
static constexpr uint32_t MMIO_GUEST_PAGE_SIZE= 0x028;
static constexpr uint32_t MMIO_QUEUE_SEL      = 0x030;
static constexpr uint32_t MMIO_QUEUE_NUM_MAX  = 0x034;
static constexpr uint32_t MMIO_QUEUE_NUM      = 0x038;
static constexpr uint32_t MMIO_QUEUE_ALIGN    = 0x03c;
static constexpr uint32_t MMIO_QUEUE_PFN      = 0x040;
static constexpr uint32_t MMIO_QUEUE_NOTIFY   = 0x050;
static constexpr uint32_t MMIO_STATUS         = 0x070;
static constexpr uint32_t MMIO_MAGIC          = 0x74726976u; // "virt"

static constexpr uint8_t  STATUS_ACKNOWLEDGE  = 1;
static constexpr uint8_t  STATUS_DRIVER       = 2;
static constexpr uint8_t  STATUS_DRIVER_OK    = 4;
static constexpr uint8_t  STATUS_FEATURES_OK  = 8;
static constexpr uint8_t  STATUS_FAILED       = 128;

// Version 2 (modern VirtIO 1.0+) additional registers.
static constexpr uint32_t MMIO_DRIVER_FEATURES_SEL = 0x024; // v2: select driver feature word
static constexpr uint32_t MMIO_QUEUE_READY         = 0x044; // v2: write 1 to activate queue
static constexpr uint32_t MMIO_QUEUE_DESC_LOW      = 0x080; // v2: descriptor table lo 32b
static constexpr uint32_t MMIO_QUEUE_DESC_HIGH     = 0x084; // v2: descriptor table hi 32b
static constexpr uint32_t MMIO_QUEUE_DRIVER_LOW    = 0x090; // v2: available ring lo 32b
static constexpr uint32_t MMIO_QUEUE_DRIVER_HIGH   = 0x094; // v2: available ring hi 32b
static constexpr uint32_t MMIO_QUEUE_DEVICE_LOW    = 0x0a0; // v2: used ring lo 32b
static constexpr uint32_t MMIO_QUEUE_DEVICE_HIGH   = 0x0a4; // v2: used ring hi 32b

// VirtIO ring descriptor flags
static constexpr uint16_t DESC_F_WRITE = 2; // device-writable (for RX bufs)

} // anonymous namespace

namespace virtio_console {

// ---- Ring constants --------------------------------------------------------

static constexpr int QS = 16; // virtqueue size (must be power of two)

// Memory layout helpers for a virtqueue:
//   desc[i]            at queue_mem + i * 16
//   avail.flags        at queue_mem + QS * 16 + 0
//   avail.idx          at queue_mem + QS * 16 + 2
//   avail.ring[i]      at queue_mem + QS * 16 + 4 + i * 2
//   used.flags         at queue_mem + 4096 + 0
//   used.idx           at queue_mem + 4096 + 2
//   used.ring[i].id    at queue_mem + 4096 + 4 + i * 8
//   used.ring[i].len   at queue_mem + 4096 + 8 + i * 8

static constexpr int AVAIL_OFFSET = QS * 16;      // 256
static constexpr int USED_OFFSET  = 4096;         // page boundary

// ---- Static ring memory ----------------------------------------------------

static uint8_t tx_mem_[8192] __attribute__((aligned(4096)));
static uint8_t rx_mem_[8192] __attribute__((aligned(4096)));

// TX data buffer: one byte per descriptor slot (we reuse slot 0 each time)
static uint8_t tx_buf_[1];

// RX data buffers: one small buffer per RX descriptor slot
static uint8_t rx_bufs_[QS];

// ---- Ring state ------------------------------------------------------------

static uint64_t base_ = 0;            // virtio-mmio base address, 0 = not inited
static bool     pci_mode_ = false;    // true = PCI transport, false = MMIO
static uint64_t tx_notify_addr_ = 0;  // PCI: MMIO address for TX queue notify
static uint64_t rx_notify_addr_ = 0;  // PCI: MMIO address for RX queue notify

static uint16_t tx_avail_idx_ = 0;    // avail ring idx (# submissions)
static uint16_t tx_last_used_ = 0;    // used ring idx we last saw (# completions)

static uint16_t rx_avail_idx_ = 0;    // avail ring idx
static uint16_t rx_last_used_ = 0;    // used ring idx we last saw

// ---- Ring accessors --------------------------------------------------------

// TX desc[i] field accessors
static inline volatile uint64_t& tx_desc_addr(int i) {
    return *reinterpret_cast<volatile uint64_t*>(tx_mem_ + i * 16 + 0);
}
static inline volatile uint32_t& tx_desc_len(int i) {
    return *reinterpret_cast<volatile uint32_t*>(tx_mem_ + i * 16 + 8);
}
static inline volatile uint16_t& tx_desc_flags(int i) {
    return *reinterpret_cast<volatile uint16_t*>(tx_mem_ + i * 16 + 12);
}

// TX avail ring
static inline volatile uint16_t& tx_avail_idx_reg() {
    return *reinterpret_cast<volatile uint16_t*>(tx_mem_ + AVAIL_OFFSET + 2);
}
static inline volatile uint16_t& tx_avail_ring(int i) {
    return *reinterpret_cast<volatile uint16_t*>(tx_mem_ + AVAIL_OFFSET + 4 + i * 2);
}

// TX used ring
static inline volatile uint16_t& tx_used_idx_reg() {
    return *reinterpret_cast<volatile uint16_t*>(tx_mem_ + USED_OFFSET + 2);
}

// RX desc[i] field accessors
static inline volatile uint64_t& rx_desc_addr(int i) {
    return *reinterpret_cast<volatile uint64_t*>(rx_mem_ + i * 16 + 0);
}
static inline volatile uint32_t& rx_desc_len(int i) {
    return *reinterpret_cast<volatile uint32_t*>(rx_mem_ + i * 16 + 8);
}
static inline volatile uint16_t& rx_desc_flags(int i) {
    return *reinterpret_cast<volatile uint16_t*>(rx_mem_ + i * 16 + 12);
}

// RX avail ring
static inline volatile uint16_t& rx_avail_idx_reg() {
    return *reinterpret_cast<volatile uint16_t*>(rx_mem_ + AVAIL_OFFSET + 2);
}
static inline volatile uint16_t& rx_avail_ring(int i) {
    return *reinterpret_cast<volatile uint16_t*>(rx_mem_ + AVAIL_OFFSET + 4 + i * 2);
}

// RX used ring
static inline volatile uint16_t& rx_used_idx_reg() {
    return *reinterpret_cast<volatile uint16_t*>(rx_mem_ + USED_OFFSET + 2);
}
static inline volatile uint32_t& rx_used_ring_id(int i) {
    return *reinterpret_cast<volatile uint32_t*>(rx_mem_ + USED_OFFSET + 4 + i * 8);
}

// ---- Queue initialisation helper -------------------------------------------

static bool init_queue(uint32_t qidx, uint8_t* mem, bool is_v2) {
    auto r32 = [](uint32_t off) { return arch::mmio_read32(base_ + off); };
    auto w32 = [](uint32_t off, uint32_t v) { arch::mmio_write32(base_ + off, v); };

    w32(MMIO_QUEUE_SEL, qidx);

    uint32_t qmax = r32(MMIO_QUEUE_NUM_MAX);
    if (qmax == 0) return false;
    uint16_t qs = (QS < (int)qmax) ? (uint16_t)QS : (uint16_t)qmax;

    w32(MMIO_QUEUE_NUM, qs);

    if (is_v2) {
        // v2: provide separate physical addresses for the three ring regions.
        uint64_t desc_addr  = (uint64_t)(uintptr_t)mem;
        uint64_t avail_addr = (uint64_t)(uintptr_t)(mem + AVAIL_OFFSET);
        uint64_t used_addr  = (uint64_t)(uintptr_t)(mem + USED_OFFSET);
        w32(MMIO_QUEUE_DESC_LOW,    (uint32_t)desc_addr);
        w32(MMIO_QUEUE_DESC_HIGH,   (uint32_t)(desc_addr  >> 32));
        w32(MMIO_QUEUE_DRIVER_LOW,  (uint32_t)avail_addr);
        w32(MMIO_QUEUE_DRIVER_HIGH, (uint32_t)(avail_addr >> 32));
        w32(MMIO_QUEUE_DEVICE_LOW,  (uint32_t)used_addr);
        w32(MMIO_QUEUE_DEVICE_HIGH, (uint32_t)(used_addr  >> 32));
        w32(MMIO_QUEUE_READY, 1);
    } else {
        // v1: single page-frame address; requires prior GUEST_PAGE_SIZE write.
        w32(MMIO_QUEUE_ALIGN, 4096);
        w32(MMIO_QUEUE_PFN,   (uint32_t)((uintptr_t)mem >> 12));
    }
    return true;
}

// ---- PCI queue init helper (uses same static ring memory) ------------------

static bool init_pci_queue(virtio_pci::Device* dev, uint32_t qidx, uint8_t* mem) {
    virtio_pci::select_queue(dev, qidx);
    uint16_t qmax = virtio_pci::get_queue_size(dev);
    if (qmax == 0) return false;
    uint16_t qs = (QS < (int)qmax) ? (uint16_t)QS : (uint16_t)qmax;
    virtio_pci::set_queue_size(dev, qs);

    uint64_t desc_addr  = (uint64_t)(uintptr_t)mem;
    uint64_t avail_addr = (uint64_t)(uintptr_t)(mem + AVAIL_OFFSET);
    uint64_t used_addr  = (uint64_t)(uintptr_t)(mem + USED_OFFSET);
    virtio_pci::set_queue_addrs(dev, desc_addr, avail_addr, used_addr);
    virtio_pci::enable_queue(dev);
    return true;
}

// ---- Public API ------------------------------------------------------------

// Brief delay for platforms (e.g. Apple VZ.framework) that process VirtIO
// config-space writes asynchronously.  10 000 nops ≈ a few microseconds on
// Apple Silicon — enough for the host I/O thread to catch up.
static inline void vz_delay() {
    for (volatile int i = 0; i < 10000; i++)
        asm volatile("nop");
}

bool init_pci(virtio_pci::Device* dev) {
    if (!dev) return false;

    pci_mode_ = true;

    // Reset → ACKNOWLEDGE → DRIVER (with inter-write delays for Apple VZ).
    virtio_pci::reset(dev);        vz_delay();
    virtio_pci::set_status(dev, STATUS_ACKNOWLEDGE);
    vz_delay();
    virtio_pci::set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    vz_delay();

    // Feature negotiation: modern VirtIO-PCI requires VIRTIO_F_VERSION_1
    // (bit 32 = word 1 bit 0).  Without it VZ rejects FEATURES_OK.
    virtio_pci::write_features(dev, 0, 0);  // word 0: no optional features
    virtio_pci::write_features(dev, 1, 1);  // word 1: VIRTIO_F_VERSION_1
    vz_delay();
    virtio_pci::set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    vz_delay();
    if (!(virtio_pci::get_status(dev) & STATUS_FEATURES_OK)) {
        virtio_pci::set_status(dev, STATUS_FAILED);
        return false;
    }

    // Zero ring memory
    for (int i = 0; i < 8192; i++) { tx_mem_[i] = 0; rx_mem_[i] = 0; }

    // Init RX queue (0) and TX queue (1)
    if (!init_pci_queue(dev, 0, rx_mem_)) {
        virtio_pci::set_status(dev, STATUS_FAILED);
        return false;
    }
    if (!init_pci_queue(dev, 1, tx_mem_)) {
        virtio_pci::set_status(dev, STATUS_FAILED);
        return false;
    }

    // Compute notify addresses for each queue
    virtio_pci::select_queue(dev, 0);
    uint16_t rx_notify_off = virtio_pci::get_queue_notify_off(dev);
    rx_notify_addr_ = virtio_pci::queue_notify_addr(dev, rx_notify_off);

    virtio_pci::select_queue(dev, 1);
    uint16_t tx_notify_off = virtio_pci::get_queue_notify_off(dev);
    tx_notify_addr_ = virtio_pci::queue_notify_addr(dev, tx_notify_off);

    // Pre-populate RX descriptors
    for (int i = 0; i < QS; i++) {
        rx_desc_addr(i)  = (uint64_t)(uintptr_t)&rx_bufs_[i];
        rx_desc_len(i)   = 1;
        rx_desc_flags(i) = DESC_F_WRITE;
        rx_avail_ring(i) = (uint16_t)i;
        rx_avail_idx_++;
    }
    asm volatile("dsb sy" ::: "memory");
    rx_avail_idx_reg() = rx_avail_idx_;
    asm volatile("dsb sy" ::: "memory");

    // Set up TX descriptor 0
    tx_desc_addr(0)  = (uint64_t)(uintptr_t)tx_buf_;
    tx_desc_len(0)   = 1;
    tx_desc_flags(0) = 0;

    // Activate device — must happen before RX kick (VZ ignores pre-DRIVER_OK kicks)
    virtio_pci::set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER |
                                STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    // Kick RX queue so the host can start sending us data.
    *reinterpret_cast<volatile uint16_t*>(rx_notify_addr_) = 0;

    // Brief pause for the host I/O thread to fully initialise after DRIVER_OK.
    // Apple VZ.framework needs this; harmless (one-time ~few ms) elsewhere.
    for (volatile int i = 0; i < 1000000; i++) asm volatile("nop");

    // Mark as initialized (base_ != 0 signals init complete)
    base_ = 1;  // non-zero sentinel for PCI mode
    return true;
}

bool init(uint64_t base_addr) {
    auto r32 = [base_addr](uint32_t off) { return arch::mmio_read32(base_addr + off); };
    auto w32 = [base_addr](uint32_t off, uint32_t v) { arch::mmio_write32(base_addr + off, v); };

    if (r32(MMIO_MAGIC_VALUE) != MMIO_MAGIC) return false;
    uint32_t ver = r32(MMIO_VERSION);
    if (ver != 1 && ver != 2) return false;  // unsupported transport version
    if (r32(MMIO_DEVICE_ID)   != 3)          return false; // must be DeviceID=3 (console)

    bool is_v2 = (ver == 2);
    base_ = base_addr;

    // Reset → ACKNOWLEDGE → DRIVER
    w32(MMIO_STATUS, 0);
    w32(MMIO_STATUS, STATUS_ACKNOWLEDGE);
    w32(MMIO_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    // Feature negotiation: we accept no optional features.
    if (is_v2) {
        // v2: write driver features for both words, then check FEATURES_OK.
        w32(MMIO_DRIVER_FEATURES_SEL, 0);
        w32(MMIO_GUEST_FEATURES, 0);   // no low features
        w32(MMIO_DRIVER_FEATURES_SEL, 1);
        w32(MMIO_GUEST_FEATURES, 0);   // no high features
        w32(MMIO_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        if (!(r32(MMIO_STATUS) & STATUS_FEATURES_OK)) {
            w32(MMIO_STATUS, STATUS_FAILED);
            base_ = 0;
            return false;
        }
    } else {
        // v1: single feature word; GuestPageSize required before queue setup.
        w32(MMIO_GUEST_FEATURES, 0);
        w32(MMIO_GUEST_PAGE_SIZE, 4096);
    }

    // Initialise RX queue (0) and TX queue (1)
    if (!init_queue(0, rx_mem_, is_v2)) {
        w32(MMIO_STATUS, STATUS_FAILED);
        base_ = 0;
        return false;
    }
    if (!init_queue(1, tx_mem_, is_v2)) {
        w32(MMIO_STATUS, STATUS_FAILED);
        base_ = 0;
        return false;
    }

    // Pre-populate RX descriptors with 1-byte buffers and submit them all.
    for (int i = 0; i < QS; i++) {
        rx_desc_addr(i)  = (uint64_t)(uintptr_t)&rx_bufs_[i];
        rx_desc_len(i)   = 1;
        rx_desc_flags(i) = DESC_F_WRITE; // device writes into this buffer
        rx_avail_ring(i) = (uint16_t)i;
        rx_avail_idx_++;
    }
    arch::dsb_st();
    rx_avail_idx_reg() = rx_avail_idx_;
    arch::dsb_sy();
    w32(MMIO_QUEUE_NOTIFY, 0); // kick RX queue

    // Set up the single TX descriptor (we reuse desc 0 for every putc).
    tx_desc_addr(0)  = (uint64_t)(uintptr_t)tx_buf_;
    tx_desc_len(0)   = 1;
    tx_desc_flags(0) = 0; // device-readable

    // Activate the device; v2 must keep FEATURES_OK set in status.
    uint32_t final_status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK;
    if (is_v2) final_status |= STATUS_FEATURES_OK;
    w32(MMIO_STATUS, final_status);
    return true;
}

void putc(char c) {
    if (base_ == 0) return;

    // Spin until the device has consumed the previous TX descriptor.
    while (tx_last_used_ < tx_avail_idx_) {
        uint16_t u = tx_used_idx_reg();
        if (u != tx_last_used_) {
            tx_last_used_ = u;
        }
        arch::cpu_relax();
    }

    // Update TX buffer and submit descriptor 0.
    tx_buf_[0] = (uint8_t)c;

    arch::dsb_st();
    tx_avail_ring(tx_avail_idx_ % QS) = 0; // descriptor index 0
    arch::dsb_st();
    tx_avail_idx_reg() = tx_avail_idx_ + 1;
    tx_avail_idx_++;
    asm volatile("dsb sy" ::: "memory");

    // Kick TX queue
    if (pci_mode_) {
        *reinterpret_cast<volatile uint16_t*>(tx_notify_addr_) = 1;
    } else {
        arch::mmio_write32(base_ + MMIO_QUEUE_NOTIFY, 1);
    }

    // Spin until the device confirms the TX.
    while (tx_used_idx_reg() == tx_last_used_) arch::cpu_relax();
    tx_last_used_ = tx_used_idx_reg();
}

int try_getc() {
    if (base_ == 0) return -1;

    uint16_t used_idx = rx_used_idx_reg();
    if (used_idx == rx_last_used_) return -1; // nothing available

    // There is a completed RX descriptor.
    int slot = rx_last_used_ % QS;
    uint32_t desc_id = rx_used_ring_id(slot);
    int c = (int)(uint8_t)rx_bufs_[desc_id];
    rx_last_used_++;

    // Resubmit the descriptor for the next incoming byte.
    rx_desc_addr(desc_id)  = (uint64_t)(uintptr_t)&rx_bufs_[desc_id];
    rx_desc_len(desc_id)   = 1;
    rx_desc_flags(desc_id) = DESC_F_WRITE;

    arch::dsb_st();
    rx_avail_ring(rx_avail_idx_ % QS) = (uint16_t)desc_id;
    asm volatile("dsb st" ::: "memory");
    rx_avail_idx_reg() = rx_avail_idx_ + 1;
    rx_avail_idx_++;
    asm volatile("dsb sy" ::: "memory");

    // Kick RX queue
    if (pci_mode_) {
        *reinterpret_cast<volatile uint16_t*>(rx_notify_addr_) = 0;
    } else {
        arch::mmio_write32(base_ + MMIO_QUEUE_NOTIFY, 0);
    }

    return c;
}

} // namespace virtio_console
