// uni/ffi.cc — C-linkage FFI wrappers for Rust interop
//
// Wraps the C++ uni:: namespace functions with extern "C" symbols
// that Rust code can call via FFI. Covers lifecycle, logging,
// configuration, TCP, and idle/events.

#include "uni/uni.h"

extern "C" {

// ---- Lifecycle / config -----------------------------------------------------

void uni_log(const char *msg) { uni::log("%s", msg); }

uint16_t uni_config_port(uint16_t default_port) {
  return uni::config_port(default_port);
}

bool uni_check_shutdown() { return uni::check_shutdown(); }

void uni_wait_for_events() { uni::wait_for_events(); }

// ---- TCP --------------------------------------------------------------------

void *uni_tcp_listen(uint16_t port) {
  return static_cast<void *>(uni::tcp::listen(port));
}

void *uni_tcp_accept(void *conn) {
  return static_cast<void *>(
      uni::tcp::accept(static_cast<uni::tcp::Connection *>(conn)));
}

bool uni_tcp_has_data(void *conn) {
  return uni::tcp::has_data(static_cast<uni::tcp::Connection *>(conn));
}

size_t uni_tcp_recv(void *conn, void *buf, size_t max_len) {
  return uni::tcp::recv(static_cast<uni::tcp::Connection *>(conn), buf,
                        max_len);
}

int uni_tcp_send(void *conn, const void *data, size_t len) {
  return uni::tcp::send(static_cast<uni::tcp::Connection *>(conn), data, len);
}

void uni_tcp_close(void *conn) {
  uni::tcp::close(static_cast<uni::tcp::Connection *>(conn));
}

bool uni_tcp_is_closed(void *conn) {
  return uni::tcp::is_closed(static_cast<uni::tcp::Connection *>(conn));
}

void uni_tcp_poll() { uni::tcp::poll(); }

} // extern "C"
