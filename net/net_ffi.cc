// net/net_ffi.cc — C-linkage FFI wrappers for Rust network stack
//
// Provides extern "C" access to kernel and driver functions that the
// Rust network stack needs: serial output, memory allocation,
// virtio-net (via Rust driver), and architecture-specific timing.

#include "kernel/serial.h"
#include "kernel/mm.h"
#include "kernel/arch.h"

// Rust driver functions (drivers/drivers.rs)
extern "C" void driver_virtio_net_get_mac(uint8_t *mac_out);
extern "C" void driver_virtio_net_send(const void *data, uint32_t len);
extern "C" int32_t driver_virtio_net_poll(void (*callback)(const uint8_t *, uint32_t));

extern "C" {

// ---- Serial output ----------------------------------------------------------

void net_serial_log(const char *msg) { serial::printf("%s", msg); }

// ---- Memory allocation ------------------------------------------------------

void *net_kmalloc(size_t size) { return mm::kmalloc(size); }

void net_kfree(void *ptr) { mm::kfree(ptr); }

// ---- Virtio-net driver (delegates to Rust) ----------------------------------

void net_virtio_get_mac(uint8_t *mac_out) {
  driver_virtio_net_get_mac(mac_out);
}

void net_virtio_send(const void *data, uint32_t len) {
  driver_virtio_net_send(data, len);
}

using PollCallback = void (*)(const uint8_t *, uint32_t);

void net_virtio_poll(PollCallback callback) {
  driver_virtio_net_poll(callback);
}

// ---- Architecture -----------------------------------------------------------

void net_arch_udelay(uint32_t us) { arch::udelay(us); }

} // extern "C"
