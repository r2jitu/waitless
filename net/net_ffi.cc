// net/net_ffi.cc — C-linkage FFI wrappers for Rust network stack
//
// Provides extern "C" access to kernel and driver functions that the
// Rust network stack needs: serial output, memory allocation,
// virtio-net, and architecture-specific timing.

#include "kernel/serial.h"
#include "kernel/mm.h"
#include "kernel/arch.h"
#include "drivers/virtio_net.h"

extern "C" {

// ---- Serial output ----------------------------------------------------------

void net_serial_log(const char *msg) { serial::printf("%s", msg); }

// ---- Memory allocation ------------------------------------------------------

void *net_kmalloc(size_t size) { return mm::kmalloc(size); }

void net_kfree(void *ptr) { mm::kfree(ptr); }

// ---- Virtio-net driver ------------------------------------------------------

void net_virtio_get_mac(uint8_t *mac_out) {
  const uint8_t *mac = virtio_net::get_mac();
  for (int i = 0; i < 6; i++)
    mac_out[i] = mac[i];
}

void net_virtio_send(const void *data, uint32_t len) {
  virtio_net::send(data, len);
}

// Callback type: void(*)(const uint8_t* data, uint32_t len)
using PollCallback = void (*)(const uint8_t *, uint32_t);

void net_virtio_poll(PollCallback callback) {
  virtio_net::poll(callback);
}

// ---- Architecture -----------------------------------------------------------

void net_arch_udelay(uint32_t us) { arch::udelay(us); }

} // extern "C"
