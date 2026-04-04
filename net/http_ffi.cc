// net/http_ffi.cc — C-linkage FFI bridge for net::http::Server and uni::
//
// Allows Rust code to use the C++ HTTP server by registering a single
// dispatch callback. The Rust dispatch function receives the request
// path and method, and returns an FFI-compatible response struct.
//
// Also wraps uni:: functions that the Rust application needs.
//
// This is a temporary bridge for the C++ → Rust migration. It will be
// removed when the HTTP server is rewritten in Rust (Phase 3).

#include "net/http.h"
#include "uni/uni.h"
#include <stdarg.h>

// ---- FFI types (must match Rust definitions) --------------------------------

struct FfiHttpResponse {
  int32_t status;
  const char *content_type;
  const char *body;
  uint64_t body_len; // 0 = use strlen(body)
};

// Dispatch callback: Rust function that handles all HTTP requests.
// path: null-terminated request path (e.g. "/health")
// method: 0=GET, 1=POST, 2=PUT, 3=DELETE, 4=HEAD, 5=UNKNOWN
using FfiHttpDispatch = FfiHttpResponse (*)(const char *path, int32_t method);

// ---- State ------------------------------------------------------------------

static FfiHttpDispatch g_dispatch = nullptr;

// The Server object is ~530KB — must live in BSS (global static).
static net::http::Server g_server;

// ---- Bridge handler ---------------------------------------------------------

// Single C++ handler that delegates all requests to the Rust dispatch function.
static net::http::Response bridge_handler(const net::http::Request &req) {
  if (g_dispatch) {
    FfiHttpResponse r = g_dispatch(req.path, static_cast<int32_t>(req.method));
    return net::http::Response{
        static_cast<int>(r.status),
        r.content_type,
        r.body,
        static_cast<size_t>(r.body_len),
    };
  }
  return net::http::Response::not_found();
}

// ---- Extern "C" API ---------------------------------------------------------

extern "C" {

// ---- HTTP server ------------------------------------------------------------

void http_server_set_dispatch(FfiHttpDispatch dispatch) {
  g_dispatch = dispatch;
  g_server.default_handler(bridge_handler);
}

void http_server_run(uint16_t port) {
  g_server.run(port);
}

// ---- uni:: wrappers ---------------------------------------------------------

void uni_log(const char *msg) { uni::log("%s", msg); }

uint16_t uni_config_port(uint16_t default_port) {
  return uni::config_port(default_port);
}

} // extern "C"
