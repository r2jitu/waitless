#pragma once
// net/http.h — Simple HTTP/1.1 server library
//
// Usage:
//   net::http::Server server(80);
//   server.route("/",       my_root_handler);
//   server.route("/health", my_health_handler);
//   server.default_handler(my_404_handler);
//   server.run();   // blocks forever — this is the event loop

#include <stdint.h>
#include <stddef.h>

// Forward declaration to avoid circular includes with net/tcp.h
namespace net { namespace tcp { struct Connection; } }

namespace net {
namespace http {

// ---- Request ----------------------------------------------------------------

struct Request {
    enum Method { GET, POST, PUT, DELETE, HEAD, UNKNOWN };

    Method method = UNKNOWN;
    char   path[256];
    char   body[8192];
    size_t body_len = 0;

    struct Header {
        char name[64];
        char value[256];
    };
    Header headers[16];
    int    header_count = 0;

    // Look up a request header by name (case-insensitive). Returns nullptr if
    // not found.
    const char* get_header(const char* name) const;
};

// ---- Response ---------------------------------------------------------------

struct Response {
    int         status       = 200;
    const char* content_type = "text/plain";
    const char* body         = "";
    size_t      body_len     = 0;   // 0 → strlen(body)

    // Convenience constructors
    static Response ok(const char* content_type, const char* body);
    static Response ok(const char* content_type, const char* body, size_t len);
    static Response not_found();
    static Response method_not_allowed();
    static Response error(int status, const char* msg);
};

// ---- Handler type -----------------------------------------------------------

using Handler = Response (*)(const Request& req);

// ---- Server -----------------------------------------------------------------

class Server {
public:
    explicit Server(uint16_t port = 80);

    // Register an exact-path handler.  Path should start with '/'.
    void route(const char* path, Handler handler);

    // Handler called when no route matches.
    void default_handler(Handler handler);

    // Run the server event loop.  This function never returns under normal
    // operation; it polls virtio-net → TCP → dispatches HTTP → sends response.
    void run();

private:
    // ---- Configuration -----
    uint16_t port_;

    struct Route {
        char    path[256];
        Handler handler;
    };
    static constexpr int MAX_ROUTES = 64;
    Route routes_[MAX_ROUTES];
    int   route_count_ = 0;
    Handler default_handler_ = nullptr;

    // ---- Active connection tracking -----
    // We handle up to 64 simultaneous HTTP connections (sufficient for a
    // unikernel — we're not doing thousands of idle keep-alive connections).
    struct ActiveConn {
        net::tcp::Connection* conn = nullptr;
        char   buf[8192];
        size_t buf_len = 0;
        bool   in_use  = false;
    };
    static constexpr int MAX_ACTIVE = 64;
    ActiveConn active_[MAX_ACTIVE];

    // ---- Helpers -----
    // Returns number of bytes consumed (>0) on success, 0 if incomplete.
    size_t      parse_request(const char* data, size_t len, Request* req) const;
    Handler     find_handler(const char* path) const;
    void        send_response(net::tcp::Connection* conn, const Response& resp,
                              bool keep_alive) const;
    const char* status_text(int status) const;
    ActiveConn* alloc_active();
    void        free_active(ActiveConn* ac);
};

} // namespace http
} // namespace net

#include "net/tcp.h"
