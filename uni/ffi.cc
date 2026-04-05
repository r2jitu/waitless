// uni/ffi.cc — Unikernel backend: extern "C" wrappers for Rust interop
//
// Provides lifecycle/config uni_* functions that the Rust HTTP server calls.
// TCP functions (uni_tcp_*) are now provided by the Rust net stack (net/stack.rs).

#include "drivers/virtio_net.h"
#include "kernel/arch.h"
#include "kernel/serial.h"

extern "C" {

// ---- Lifecycle / config -----------------------------------------------------

void uni_log(const char *msg) { serial::printf("%s", msg); }

uint16_t uni_config_port(uint16_t default_port) { return default_port; }

bool uni_check_shutdown() { return serial::check_shutdown(); }

void uni_wait_for_events() {
  if (virtio_net::irq_idle_supported()) {
    arch::mask_irq();
    virtio_net::arm_rx_interrupts();
    if (!virtio_net::has_pending_rx()) {
      arch::idle();
    }
    arch::unmask_irq();
  } else {
    arch::cpu_relax();
  }
}

} // extern "C"
