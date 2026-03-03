// drivers/pci.cc -- PCI bus enumeration implementation
//
// x86_64: Configuration Space Access Mechanism #1 (I/O ports 0xCF8/0xCFC).
// aarch64: ECAM (Enhanced Configuration Access Mechanism) — memory-mapped at
//          0x4010000000 on the QEMU virt machine (QEMU 10.x, confirmed via DTB).

#include "drivers/pci.h"
#include "kernel/arch.h"
#if defined(__aarch64__)
#include "kernel/fdt.h"
#include "kernel/aarch64/mmu.h"
#endif

// PCI runs before serial on VZ (early PCI scan for console discovery).
// Use a late-bound printf that's safe to call even when serial is not yet up.
// Declared in serial.h, but we avoid the header dep to break a build cycle.
namespace serial { void printf(const char* fmt, ...); }

namespace pci {

// ============================================================================
// Internal state
// ============================================================================

static Device devices_[MAX_DEVICES];
static int device_count_ = 0;

// ============================================================================
// Configuration space access
// ============================================================================

#if defined(__aarch64__)

// ECAM base — set dynamically from FDT in pci::init().
// Default to QEMU's address (0x4010000000); overridden when FDT provides one.
static uint64_t g_ecam_base = 0x4010000000ULL;

// PCIe resource windows for BAR assignment (QEMU -kernel only, not VZ).
// QEMU does not run firmware to assign BAR addresses when using -kernel, so
// we do a minimal PCI resource allocation here.  VZ pre-assigns BARs, so
// these are only used as fallback.
static constexpr uint64_t PCI_MEM_START = 0x10000000ULL;

static uint64_t g_pci_io_next  = 0x1000;
static uint64_t g_pci_mem_next = PCI_MEM_START;

// Probe one BAR, assign a resource, and update dev.bar[i].
// Returns the number of BAR slots consumed (1 for 32-bit, 2 for 64-bit).
// optnone: prevent the compiler from combining adjacent uint32_t writes into a
// single 64-bit store (str x), which would be unaligned in the Device struct.
__attribute__((optnone))
static int assign_bar(Device& dev, int i) {
    uint8_t off = 0x10 + i * 4;
    uint32_t orig = read_config(dev.bus, dev.slot, dev.func, off);

    if (orig == 0 || orig == 0xFFFFFFFF) return 1;  // not implemented

    // Probe size: write all-ones, read back, restore
    write_config(dev.bus, dev.slot, dev.func, off, 0xFFFFFFFF);
    uint32_t probe = read_config(dev.bus, dev.slot, dev.func, off);
    write_config(dev.bus, dev.slot, dev.func, off, orig);

    bool is_io    = (orig & 0x1);
    bool is_64bit = !is_io && ((orig & 0x6) == 0x4);

    if (is_io) {
        uint32_t size = ~(probe & ~0x3u) + 1;
        if (size == 0 || size > 0x10000) return 1;
        uint64_t port = (g_pci_io_next + size - 1) & ~(uint64_t)(size - 1);
        g_pci_io_next = port + size;
        write_config(dev.bus, dev.slot, dev.func, off, (uint32_t)(port | 0x1));
        dev.bar[i] = (uint32_t)(port | 0x1);
    } else if (is_64bit) {
        // 64-bit BAR: probe high half too
        uint8_t off_hi = off + 4;
        write_config(dev.bus, dev.slot, dev.func, off_hi, 0xFFFFFFFF);
        uint32_t probe_hi = read_config(dev.bus, dev.slot, dev.func, off_hi);
        write_config(dev.bus, dev.slot, dev.func, off_hi, 0);  // keep high = 0
        uint64_t sz64 = ~(((uint64_t)probe_hi << 32) | (probe & ~0xFu)) + 1;
        if (sz64 == 0) { i++; return 2; }
        uint64_t addr = (g_pci_mem_next + sz64 - 1) & ~(sz64 - 1);
        g_pci_mem_next = addr + sz64;
        write_config(dev.bus, dev.slot, dev.func, off,    (uint32_t)addr);
        write_config(dev.bus, dev.slot, dev.func, off_hi, (uint32_t)(addr >> 32));
        dev.bar[i]   = (uint32_t)addr;
        dev.bar[i+1] = (uint32_t)(addr >> 32);
        return 2;
    } else {
        uint32_t size = ~(probe & ~0xFu) + 1;
        if (size == 0) return 1;
        uint64_t addr = (g_pci_mem_next + size - 1) & ~(uint64_t)(size - 1);
        g_pci_mem_next = addr + size;
        write_config(dev.bus, dev.slot, dev.func, off, (uint32_t)addr);
        dev.bar[i] = (uint32_t)addr;
    }
    return 1;
}

// Assign BAR addresses to an endpoint device and enable I/O + memory access.
// If firmware (VZ) already enabled memory space, BARs are pre-assigned —
// re-probing would corrupt PCIe bridge windows and cause synchronous exceptions.
__attribute__((optnone))
static void assign_bars(Device& dev) {
    if ((dev.header_type & 0x7F) != 0x00) return;  // only type-0 endpoints

    // Check if firmware already assigned BARs (Memory Space Enable set)
    uint32_t cmd = read_config(dev.bus, dev.slot, dev.func, 0x04);
    if (cmd & 0x2) return;  // trust firmware BAR assignments

    for (int i = 0; i < 6; ) {
        i += assign_bar(dev, i);
    }
    // Enable I/O space + memory space in the PCI command register
    cmd = read_config(dev.bus, dev.slot, dev.func, 0x04);
    cmd |= 0x3;
    write_config(dev.bus, dev.slot, dev.func, 0x04, cmd);
}

static volatile uint32_t* ecam_ptr(uint8_t bus, uint8_t slot,
                                    uint8_t func, uint8_t offset) {
    uint64_t addr = g_ecam_base
                  + ((uint64_t)bus  << 20)
                  + ((uint64_t)slot << 15)
                  + ((uint64_t)func << 12)
                  + ((uint64_t)(offset & 0xFC));
    return reinterpret_cast<volatile uint32_t*>(addr);
}

uint32_t read_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    return *ecam_ptr(bus, slot, func, offset);
}

void write_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset,
                  uint32_t value) {
    *ecam_ptr(bus, slot, func, offset) = value;
}

#else  // x86_64: I/O port-based config access mechanism #1

uint32_t read_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t address = (1u << 31)
                     | ((uint32_t)bus  << 16)
                     | ((uint32_t)slot << 11)
                     | ((uint32_t)func << 8)
                     | ((uint32_t)offset & 0xFC);
    arch::outl(CONFIG_ADDRESS, address);
    return arch::inl(CONFIG_DATA);
}

void write_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset,
                  uint32_t value) {
    uint32_t address = (1u << 31)
                     | ((uint32_t)bus  << 16)
                     | ((uint32_t)slot << 11)
                     | ((uint32_t)func << 8)
                     | ((uint32_t)offset & 0xFC);
    arch::outl(CONFIG_ADDRESS, address);
    arch::outl(CONFIG_DATA, value);
}

#endif  // __aarch64__

// ============================================================================
// Bus enumeration
// ============================================================================

// Read a single device's configuration and store it in the device list.
// Returns true if a valid device was found at this BDF (bus/device/function).
static bool probe_function(uint8_t bus, uint8_t slot, uint8_t func) {
    uint32_t reg0 = read_config(bus, slot, func, 0x00);
    uint16_t vendor_id = reg0 & 0xFFFF;

    // vendor_id == 0xFFFF means no device present
    if (vendor_id == 0xFFFF) {
        return false;
    }

    if (device_count_ >= MAX_DEVICES) {
        return false;
    }

    Device& dev = devices_[device_count_];
    dev.bus  = bus;
    dev.slot = slot;
    dev.func = func;

    dev.vendor_id = vendor_id;
    dev.device_id = (reg0 >> 16) & 0xFFFF;

    // Register 0x08: revision (7:0), prog_if (15:8), subclass (23:16), class (31:24)
    uint32_t reg2 = read_config(bus, slot, func, 0x08);
    dev.prog_if    = (reg2 >> 8)  & 0xFF;
    dev.subclass   = (reg2 >> 16) & 0xFF;
    dev.class_code = (reg2 >> 24) & 0xFF;

    // Register 0x0C: cache line, latency, header type, BIST
    uint32_t reg3 = read_config(bus, slot, func, 0x0C);
    dev.header_type = (reg3 >> 16) & 0xFF;

    // Read all 6 BARs (only valid for header type 0x00)
    for (int i = 0; i < 6; i++) {
        dev.bar[i] = read_config(bus, slot, func, 0x10 + i * 4);
    }

#if defined(__aarch64__)
    // Assign BARs if firmware hasn't done so (Memory Space Enable not set).
    assign_bars(dev);
    // Re-read BARs: assign_bars() may have written new addresses to config
    // space.  Refresh dev.bar[] so virtio_pci::read_bar64() gets current
    // values.  Safe to call even when assign_bars() was a no-op.
    for (int i = 0; i < 6; i++) {
        dev.bar[i] = read_config(bus, slot, func, 0x10 + i * 4);
    }
#endif

    serial::printf("PCI %02x:%02x.%x -- %04x:%04x class %02x:%02x\n",
                   bus, slot, func, dev.vendor_id, dev.device_id,
                   dev.class_code, dev.subclass);

    device_count_++;
    return true;
}

static bool initialized_ = false;

void init() {
    if (initialized_) return;  // already scanned
    initialized_ = true;
    device_count_ = 0;

#if defined(__aarch64__)
    // Set ECAM base from FDT (VZ uses a dynamic address; QEMU uses 0x4010000000).
    const fdt::Info& fdt = fdt::info();
    if (fdt.pcie_ecam_base != 0) {
        g_ecam_base = fdt.pcie_ecam_base;

        // Map the ECAM region if it's above 4GB (below 4GB is already mapped)
        if (g_ecam_base >= 0x100000000ULL) {
            uint64_t ecam_size = fdt.pcie_ecam_size ? fdt.pcie_ecam_size : (256ULL << 20);
            mmu::map_device_range(g_ecam_base, ecam_size);
        }
    }
#endif

#if defined(__aarch64__)
    serial::printf("PCI: scanning buses (ECAM at 0x%lx)...\n", g_ecam_base);
#else
    serial::printf("PCI: scanning buses...\n");
#endif

    for (int bus = 0; bus < 1; bus++) {  // DEBUG: bus 0 only to isolate crash
        for (int slot = 0; slot < 32; slot++) {
            // Check function 0 first
            uint32_t reg0 = read_config(bus, slot, 0, 0x00);
            uint16_t vendor_id = reg0 & 0xFFFF;
            if (vendor_id == 0xFFFF) {
                continue; // No device at this slot
            }

            probe_function(bus, slot, 0);

            // Check if this is a multi-function device (bit 7 of header_type)
            uint32_t reg3 = read_config(bus, slot, 0, 0x0C);
            uint8_t header_type = (reg3 >> 16) & 0xFF;
            if (header_type & 0x80) {
                // Multi-function device: probe functions 1-7
                for (int func = 1; func < 8; func++) {
                    probe_function(bus, slot, func);
                }
            }
        }
    }

    serial::printf("PCI: found %d device(s)\n", device_count_);
}

// ============================================================================
// Device lookup
// ============================================================================

Device* find_device(uint16_t vendor_id, uint16_t device_id) {
    for (int i = 0; i < device_count_; i++) {
        if (devices_[i].vendor_id == vendor_id &&
            devices_[i].device_id == device_id) {
            return &devices_[i];
        }
    }
    return nullptr;
}

Device* find_by_class(uint8_t class_code, uint8_t subclass) {
    for (int i = 0; i < device_count_; i++) {
        if (devices_[i].class_code == class_code &&
            devices_[i].subclass == subclass) {
            return &devices_[i];
        }
    }
    return nullptr;
}

const Device* get_devices(int* count) {
    if (count) {
        *count = device_count_;
    }
    return devices_;
}

// ============================================================================
// Device configuration helpers
// ============================================================================

void enable_bus_mastering(const Device& dev) {
    // PCI Command register is at offset 0x04, lower 16 bits
    uint32_t cmd = read_config(dev.bus, dev.slot, dev.func, 0x04);
    cmd |= (1 << 2); // Set Bus Master Enable bit
    write_config(dev.bus, dev.slot, dev.func, 0x04, cmd);
}

uint32_t read_bar(const Device& dev, int bar_idx) {
    if (bar_idx < 0 || bar_idx >= 6) {
        return 0;
    }

    uint32_t bar = read_config(dev.bus, dev.slot, dev.func, 0x10 + bar_idx * 4);

    if (bar & 0x01) {
        // I/O space BAR: bit 0 = 1 indicates I/O
        // Mask off the lower 2 bits (type indicator bits)
        return bar & ~0x03u;
    } else {
        // Memory space BAR: bit 0 = 0 indicates memory
        // Bits 2-1: 00 = 32-bit, 10 = 64-bit
        // Mask off the lower 4 bits (type and prefetch bits)
        return bar & ~0x0Fu;
    }
}

uint64_t read_bar64(const Device& dev, int bar_idx) {
    if (bar_idx < 0 || bar_idx >= 6) return 0;

    uint32_t bar = dev.bar[bar_idx];
    if (bar & 0x01) {
        // I/O BAR — return 32-bit address
        return (uint64_t)(bar & ~0x03u);
    }

    // Memory BAR — check if 64-bit (type bits [2:1] = 0b10)
    bool is_64bit = ((bar & 0x6) == 0x4);
    uint64_t addr = (uint64_t)(bar & ~0x0Fu);

    if (is_64bit && bar_idx < 5) {
        addr |= (uint64_t)dev.bar[bar_idx + 1] << 32;
    }

    return addr;
}

} // namespace pci
