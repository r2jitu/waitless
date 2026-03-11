#pragma once
// uni/uni.h — Interface between the application and the platform backend.
//
// Two implementations are provided:
//   uni/unikernel.cc — delegates to kernel/serial, net/tcp, kernel/arch,
//                      and drivers/virtio_net (bare-metal unikernel)
//   uni/native.cc    — POSIX sockets + stdio (host process, for
//                      benchmarking and debugging)
//
// All code above this layer (http.cc, apps) depends only on this header.

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

namespace uni {

// ---- Lifecycle -------------------------------------------------------

// One-time initialization — called by the native entry point (main.cc).
// On the unikernel this is a no-op; kernel/entry.cc handles initialization.
void init_native();

// Shut down the system (arch::shutdown on unikernel, exit(0) natively).
[[noreturn]] void shutdown();

// True if a shutdown signal has been received
// (serial 0x03 / Ctrl-C on unikernel; SIGINT natively).
bool check_shutdown();

// ---- Configuration ---------------------------------------------------

// Returns the configured value for a port.
// On native: returns the $PORT env var (parsed by init_native()), if set;
//            otherwise returns default_port.
// On unikernel: always returns default_port (no runtime config).
// Call from uni_main() to make ports overridable without changing app code.
uint16_t config_port(uint16_t default_port);

// ---- Logging ---------------------------------------------------------

// Minimal printf — same format specifiers as serial::printf.
// On unikernel: writes to serial console.  On native: writes to stderr.
void log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// ---- Idle ------------------------------------------------------------

// Called by the event loop when there is nothing to do.
// Blocks until the next network event (or a short timeout).
// On unikernel: NAPI-style WFI with IRQ masking.
// On native:    poll() with a short timeout.
void wait_for_events();

// ---- TCP -------------------------------------------------------------

namespace tcp {

// Opaque connection handle.  Only the platform implementation defines the
// layout; all callers hold Connection* pointers and never create values.
struct Connection;

// Create a listening socket bound to the given port.  Returns null on error.
Connection *listen(uint16_t port);

// Accept a pending incoming connection on a listener.
// Returns null if no connection is ready (non-blocking).
Connection *accept(Connection *listener);

// True if the connection has received data waiting to be read.
bool has_data(Connection *conn);

// Read from a connection's receive buffer.
// Returns bytes read; returns 0 if no data is available (non-blocking).
size_t recv(Connection *conn, void *buf, size_t max_len);

// Send data on an established connection.
// Returns bytes sent, or -1 on error.
int send(Connection *conn, const void *data, size_t len);

// Close a connection gracefully.
void close(Connection *conn);

// Drive the network stack — processes received packets and updates state.
// Call once per event loop iteration before checking for new data.
void poll();

// True if the connection is in the CLOSED state (dead / disconnected).
bool is_closed(Connection *conn);

} // namespace tcp
} // namespace uni
