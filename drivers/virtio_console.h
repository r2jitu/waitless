#pragma once
// drivers/virtio_console.h — VirtIO console driver (DeviceID = 3)
//
// Provides serial I/O through the virtio-console device over either
// virtio-mmio (QEMU) or modern virtio-pci (VZ.framework, any PCI host).
//
// Uses statically-allocated ring buffers in BSS so init() / init_pci()
// can be called before mm::init() (no dynamic allocation required).
//
// Queue assignment (virtio-console port 0):
//   Queue 0: receiveq  — incoming bytes from host (stdin)
//   Queue 1: transmitq — outgoing bytes to host (stdout)

#include <stdint.h>

// Forward declaration to avoid header dependency cycle
namespace virtio_pci { struct Device; }

namespace virtio_console {

// Probe and initialise the virtio-mmio console at base_addr.
// Returns true on success, false if the device is not a console (DeviceID ≠ 3)
// or if initialisation fails.
bool init(uint64_t base_addr);

// Initialise via modern virtio-PCI transport (works on any platform with
// PCI, including Apple VZ.framework).  Uses the same static BSS rings —
// safe to call before mm::init().
bool init_pci(virtio_pci::Device* dev);

// Write one byte to the console.  Blocks briefly until the device accepts it.
void putc(char c);

// Return the next byte from the console receive queue, or -1 if empty.
int  try_getc();

} // namespace virtio_console
