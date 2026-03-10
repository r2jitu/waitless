// UniKernel Example: HTTP Web Server
//
// This is an idiomatic C++ web server that runs directly on the unikernel.
// All network I/O goes through direct function calls to the virtio-net
// driver and TCP/IP stack — no kernel syscalls, no context switches.

#include "kernel/serial.h"
#include "net/http.h"

// --- Request Handlers ---

static net::http::Response handle_index(const net::http::Request &req) {
  (void)req;
  const char *html =
      "<!DOCTYPE html>"
      "<html><head><title>UniKernel</title>"
      "<style>"
      "body { font-family: system-ui, sans-serif; max-width: 800px; "
      "margin: 40px auto; padding: 0 20px; background: #0a0a0a; color: "
      "#e0e0e0; }"
      "h1 { color: #4fc3f7; } pre { background: #1a1a2e; padding: 16px; "
      "border-radius: 8px; overflow-x: auto; } a { color: #4fc3f7; }"
      ".stat { display: inline-block; margin: 8px 16px 8px 0; padding: 8px "
      "16px; "
      "background: #1a1a2e; border-radius: 4px; }"
      "</style></head><body>"
      "<h1>UniKernel Web Server</h1>"
      "<p>Running directly on bare metal — no OS kernel, no syscalls.</p>"
      "<div>"
      "<span class='stat'>Ring 0 execution</span>"
      "<span class='stat'>Single address space</span>"
      "<span class='stat'>In-process I/O</span>"
      "<span class='stat'>Virtio-net driver</span>"
      "</div>"
      "<h2>Architecture</h2>"
      "<pre>"
      "Application (this server)\n"
      "    |  direct function call\n"
      "    v\n"
      "HTTP parser (net::http)\n"
      "    |  direct function call\n"
      "    v\n"
      "TCP stack (net::tcp)\n"
      "    |  direct function call\n"
      "    v\n"
      "IP + ARP (net::ipv4, net::arp)\n"
      "    |  direct function call\n"
      "    v\n"
      "Virtio-net driver (drivers::virtio_net)\n"
      "    |  MMIO / port I/O\n"
      "    v\n"
      "Virtual NIC (hypervisor)\n"
      "</pre>"
      "<h2>Endpoints</h2>"
      "<ul>"
      "<li><a href='/'>/ </a> — this page</li>"
      "<li><a href='/health'>/health</a> — health check (JSON)</li>"
      "<li><a href='/stats'>/stats</a> — runtime statistics</li>"
      "</ul>"
      "<p><small>Built with UniKernel v0.1.0</small></p>"
      "</body></html>";

  return net::http::Response::ok("text/html", html);
}

static net::http::Response handle_health(const net::http::Request &req) {
  (void)req;
  return net::http::Response::ok(
      "application/json",
      "{\"status\":\"ok\",\"runtime\":\"unikernel\",\"version\":\"0.1.0\"}");
}

static net::http::Response handle_stats(const net::http::Request &req) {
  (void)req;
  // In a real app, you'd gather actual stats from mm::, tcp::, etc.
  return net::http::Response::ok("application/json",
                                 "{\"connections_active\":0,"
                                 "\"total_requests\":0,"
                                 "\"memory_free_mb\":0,"
                                 "\"uptime_seconds\":0}");
}

static net::http::Response handle_default(const net::http::Request &req) {
  (void)req;
  return net::http::Response::not_found();
}

// --- Application Entry Point ---

// The Server object is ~530KB (64 ActiveConn × ~8KB each + routes).
// It must live in BSS (global static), not on the 64KB kernel stack.
static net::http::Server server(80);

extern "C" int uni_main() {
  serial::printf("Starting HTTP server on port 80...\n");

  server.route("/", handle_index);
  server.route("/health", handle_health);
  server.route("/stats", handle_stats);
  server.default_handler(handle_default);

  serial::printf("Routes registered. Entering event loop.\n");

  // This runs the event loop — polls virtio-net, processes TCP,
  // parses HTTP requests, dispatches to handlers, sends responses.
  // All via direct function calls. No syscalls anywhere.
  server.run();

  // If we reach here, the server exited (only via check_shutdown)
  serial::printf("[uni_main] server.run() returned — shutting down\n");
  return 0;
}
