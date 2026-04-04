// uni/ffi.cc — Unikernel backend: extern "C" wrappers for Rust interop
//
// Provides the uni_* extern "C" functions that the Rust HTTP server calls.
// Delegates directly to the bare-metal C++ APIs: kernel/serial, kernel/arch,
// drivers/virtio_net, and net/tcp. No intermediate uni:: namespace.
//
// The native backend (native.cc) provides the same extern "C" symbols
// using POSIX sockets instead; the linker selects one or the other.

#include "drivers/virtio_net.h"
#include "kernel/arch.h"
#include "kernel/serial.h"
#include "net/tcp.h"

#include <stdarg.h>

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

// ---- TCP (wraps net::tcp directly) ------------------------------------------

void *uni_tcp_listen(uint16_t port) {
  return static_cast<void *>(net::tcp::listen(port));
}

void *uni_tcp_accept(void *conn) {
  return static_cast<void *>(
      net::tcp::accept(static_cast<net::tcp::Connection *>(conn)));
}

bool uni_tcp_has_data(void *conn) {
  return net::tcp::has_data(static_cast<net::tcp::Connection *>(conn));
}

size_t uni_tcp_recv(void *conn, void *buf, size_t max_len) {
  return net::tcp::recv(static_cast<net::tcp::Connection *>(conn), buf,
                        max_len);
}

int uni_tcp_send(void *conn, const void *data, size_t len) {
  return net::tcp::send(static_cast<net::tcp::Connection *>(conn), data, len);
}

void uni_tcp_close(void *conn) {
  net::tcp::close(static_cast<net::tcp::Connection *>(conn));
}

bool uni_tcp_is_closed(void *conn) {
  auto *c = static_cast<net::tcp::Connection *>(conn);
  if (!c)
    return true;
  return c->state == net::tcp::State::CLOSED;
}

void uni_tcp_poll() { net::tcp::poll(); }

} // extern "C"
