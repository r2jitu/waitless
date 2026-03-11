// uni/unikernel.cc — uni:: implementation for the bare-metal unikernel.
//
// Delegates to:
//   kernel/serial      → uni::log, uni::check_shutdown
//   kernel/arch        → uni::shutdown, uni::wait_for_events (idle)
//   drivers/virtio_net → uni::wait_for_events (NAPI IRQ dance)
//   net/tcp            → uni::tcp::*

#include "uni/uni.h"

#include "drivers/virtio_net.h"
#include "kernel/arch.h"
#include "kernel/serial.h"
#include "net/tcp.h"

#include <stdarg.h>

// ---- Connection type ---------------------------------------------------------
//
// uni::tcp::Connection is an opaque alias for net::tcp::Connection.
// We define an empty struct body here to satisfy the forward declaration in
// platform.h, then reinterpret_cast between the two pointer types.  This is
// safe because:
//   1. Only this file ever dereferences through the net::tcp::Connection type.
//   2. The underlying objects are owned by net::tcp's static pool.
//   3. The cast is pointer-identity — no arithmetic or layout assumptions.

struct uni::tcp::Connection {};

static inline uni::tcp::Connection *wrap(net::tcp::Connection *c) {
  return reinterpret_cast<uni::tcp::Connection *>(c);
}
static inline net::tcp::Connection *unwrap(uni::tcp::Connection *c) {
  return reinterpret_cast<net::tcp::Connection *>(c);
}

// ---- Lifecycle ---------------------------------------------------------------

void uni::init_native() {} // no-op: kernel/entry.cc handles initialization

uint16_t uni::config_port(uint16_t default_port) { return default_port; }

[[noreturn]] void uni::shutdown() { arch::shutdown(); }

bool uni::check_shutdown() { return serial::check_shutdown(); }

// ---- Logging -----------------------------------------------------------------

void uni::log(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  serial::vprintf(fmt, ap);
  va_end(ap);
}

// ---- Idle --------------------------------------------------------------------

void uni::wait_for_events() {
  if (virtio_net::irq_idle_supported()) {
    // Race-free idle pattern (see net/http.cc comment):
    //   mask → arm_rx → check_pending → WFI → unmask
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

// ---- TCP ---------------------------------------------------------------------

uni::tcp::Connection *uni::tcp::listen(uint16_t port) {
  return wrap(net::tcp::listen(port));
}

uni::tcp::Connection *uni::tcp::accept(Connection *listener) {
  return wrap(net::tcp::accept(unwrap(listener)));
}

bool uni::tcp::has_data(Connection *conn) {
  return net::tcp::has_data(unwrap(conn));
}

size_t uni::tcp::recv(Connection *conn, void *buf, size_t max_len) {
  return net::tcp::recv(unwrap(conn), buf, max_len);
}

int uni::tcp::send(Connection *conn, const void *data, size_t len) {
  return net::tcp::send(unwrap(conn), data, len);
}

void uni::tcp::close(Connection *conn) {
  net::tcp::close(unwrap(conn));
}

void uni::tcp::poll() { net::tcp::poll(); }

bool uni::tcp::is_closed(Connection *conn) {
  if (!conn)
    return true;
  return unwrap(conn)->state == net::tcp::State::CLOSED;
}
