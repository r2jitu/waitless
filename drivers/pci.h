#pragma once

// drivers/pci.h -- PCI bus enumeration via Configuration Space Access Mechanism
// #1
//
// This is a library, not a kernel module. Applications call these functions
// directly in the same address space -- no syscalls, no mode switches.
//
// PCI configuration space is accessed through two I/O ports:
//   0xCF8 (CONFIG_ADDRESS) -- write the address of the register to access
//   0xCFC (CONFIG_DATA)    -- read/write the 32-bit data at that address

#include <stddef.h>
#include <stdint.h>

namespace pci {

// ============================================================================
// Constants
// ============================================================================

static constexpr uint16_t CONFIG_ADDRESS = 0xCF8;
static constexpr uint16_t CONFIG_DATA = 0xCFC;

static constexpr int MAX_DEVICES = 64;

// ============================================================================
// PCI Device descriptor
// ============================================================================

struct Device {
  uint8_t bus, slot, func;
  uint16_t vendor_id, device_id;
  uint8_t class_code, subclass, prog_if;
  uint8_t header_type;
  uint32_t bar[6];
};

// ============================================================================
// Configuration space access
// ============================================================================

// Read a 32-bit value from PCI configuration space.
// offset must be 4-byte aligned (low 2 bits are masked off).
uint32_t read_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);

// Write a 32-bit value to PCI configuration space.
void write_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset,
                  uint32_t value);

// ============================================================================
// Bus enumeration
// ============================================================================

// Scan all PCI buses and populate the internal device list.
// Prints each discovered device to the serial console.
void init();

// ============================================================================
// Device lookup
// ============================================================================

// Find a device by vendor and device ID. Returns nullptr if not found.
Device *find_device(uint16_t vendor_id, uint16_t device_id);

// Find a device by class code and subclass. Returns nullptr if not found.
Device *find_by_class(uint8_t class_code, uint8_t subclass);

// Get the full list of discovered devices. Sets *count to the number found.
const Device *get_devices(int *count);

// ============================================================================
// Device configuration helpers
// ============================================================================

// Enable PCI bus mastering (set bit 2 of the Command register at offset 0x04).
// Required for DMA-capable devices like virtio.
void enable_bus_mastering(const Device &dev);

// Read and decode a Base Address Register (32-bit result).
// For I/O BARs (bit 0 set): masks off lower 2 bits.
// For memory BARs: masks off lower 4 bits. Checks bits 1-2 for 32/64-bit type.
uint32_t read_bar(const Device &dev, int bar_idx);

// Read a 64-bit BAR address.  For 64-bit memory BARs (type bits [2:1] = 0b10),
// combines bar[idx] and bar[idx+1].  For 32-bit BARs, returns the 32-bit value.
// Essential for VZ.framework which places BARs above 4GB.
uint64_t read_bar64(const Device &dev, int bar_idx);

} // namespace pci
