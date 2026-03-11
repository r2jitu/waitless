// net/http.cc — HTTP/1.1 server implementation
//
// Design:
//   • Non-blocking cooperative model: Server::run() is an infinite loop that
//     calls uni::tcp::poll() to drive the network stack, checks for new
//     connections via uni::tcp::accept(), reads data from established
//     connections, parses requests, dispatches to handlers, and sends responses.
//   • HTTP/1.1 keep-alive: connections stay open after each response and serve
//     multiple requests.  The client signals close via "Connection: close"
//     header.
//   • Zero copies at the app level: the TCP receive buffer is read directly
//     into the request parser — no extra memcpy between layers.

#include "net/http.h"
#include "uni/uni.h"

extern "C" size_t strlen(const char *s);
extern "C" int strcmp(const char *a, const char *b);
extern "C" int strncmp(const char *a, const char *b, size_t n);
extern "C" void *memcpy(void *dst, const void *src, size_t n);
extern "C" void *memset(void *dst, int c, size_t n);
extern "C" char *strcpy(char *dst, const char *src);
extern "C" char *strncpy(char *dst, const char *src, size_t n);

namespace net {
namespace http {

// ---- Helpers ----------------------------------------------------------------

// Minimal integer formatter into a fixed buffer. Returns number of chars written.
static int fmt_int(char *buf, size_t buflen, int n) {
  if (buflen == 0)
    return 0;
  if (n == 0) {
    buf[0] = '0';
    return 1;
  }

  char tmp[32];
  int len = 0;
  bool neg = (n < 0);
  unsigned u = neg ? (unsigned)(-(long long)n) : (unsigned)n;

  while (u > 0) {
    tmp[len++] = '0' + (u % 10);
    u /= 10;
  }
  if (neg)
    tmp[len++] = '-';

  int out = 0;
  for (int i = len - 1; i >= 0 && (size_t)out < buflen - 1; --i)
    buf[out++] = tmp[i];
  buf[out] = '\0';
  return out;
}

// Case-insensitive ASCII comparison (for HTTP header names)
static bool str_iequal(const char *a, const char *b) {
  while (*a && *b) {
    char ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
    char cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
    if (ca != cb)
      return false;
    ++a;
    ++b;
  }
  return *a == *b;
}

// ---- Response ---------------------------------------------------------------

Response Response::ok(const char *content_type, const char *body) {
  return {200, content_type, body, 0};
}

Response Response::ok(const char *content_type, const char *body, size_t len) {
  return {200, content_type, body, len};
}

Response Response::not_found() {
  return {404, "text/plain", "404 Not Found", 0};
}

Response Response::method_not_allowed() {
  return {405, "text/plain", "405 Method Not Allowed", 0};
}

Response Response::error(int status, const char *msg) {
  return {status, "text/plain", msg, 0};
}

// ---- Request ----------------------------------------------------------------

const char *Request::get_header(const char *name) const {
  for (int i = 0; i < header_count; ++i) {
    if (str_iequal(headers[i].name, name))
      return headers[i].value;
  }
  return nullptr;
}

// ---- Server -----------------------------------------------------------------

Server::Server(uint16_t port) : port_(port), route_count_(0) {
  memset(routes_, 0, sizeof(routes_));
  memset(active_, 0, sizeof(active_));
}

void Server::route(const char *path, Handler handler) {
  if (route_count_ >= MAX_ROUTES) {
    uni::log("http: too many routes (max %d)\n", MAX_ROUTES);
    return;
  }
  strncpy(routes_[route_count_].path, path, sizeof(routes_[0].path) - 1);
  routes_[route_count_].handler = handler;
  ++route_count_;
}

void Server::default_handler(Handler handler) { default_handler_ = handler; }

Server::ActiveConn *Server::alloc_active() {
  for (int i = 0; i < MAX_ACTIVE; ++i) {
    if (!active_[i].in_use) {
      active_[i].in_use = true;
      active_[i].buf_len = 0;
      active_[i].conn = nullptr;
      return &active_[i];
    }
  }
  return nullptr;
}

void Server::free_active(ActiveConn *ac) {
  ac->in_use = false;
  ac->buf_len = 0;
  ac->conn = nullptr;
}

const char *Server::status_text(int status) const {
  switch (status) {
  case 200: return "OK";
  case 201: return "Created";
  case 204: return "No Content";
  case 301: return "Moved Permanently";
  case 302: return "Found";
  case 304: return "Not Modified";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 500: return "Internal Server Error";
  case 501: return "Not Implemented";
  case 503: return "Service Unavailable";
  default:  return "Unknown";
  }
}

Handler Server::find_handler(const char *path) const {
  // Exact match first
  for (int i = 0; i < route_count_; ++i) {
    if (strcmp(routes_[i].path, path) == 0)
      return routes_[i].handler;
  }
  // Prefix match (e.g. "/api" matches "/api/v1/foo")
  for (int i = 0; i < route_count_; ++i) {
    size_t plen = strlen(routes_[i].path);
    if (plen > 1 && strncmp(routes_[i].path, path, plen) == 0)
      return routes_[i].handler;
  }
  return default_handler_;
}

// ---- HTTP request parser ----------------------------------------------------
// Returns bytes consumed (> 0) when a complete request is parsed, 0 if incomplete.

size_t Server::parse_request(const char *data, size_t len, Request *req) const {
  memset(req, 0, sizeof(*req));

  // Find end of headers ("\r\n\r\n")
  const char *header_end = nullptr;
  for (size_t i = 0; i + 3 < len; ++i) {
    if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' &&
        data[i + 3] == '\n') {
      header_end = data + i;
      break;
    }
  }
  if (!header_end)
    return 0; // incomplete headers

  // Parse request line: "METHOD /path HTTP/1.x\r\n"
  const char *p = data;

  if (strncmp(p, "GET ", 4) == 0)         { req->method = Request::GET;     p += 4; }
  else if (strncmp(p, "POST ", 5) == 0)   { req->method = Request::POST;    p += 5; }
  else if (strncmp(p, "PUT ", 4) == 0)    { req->method = Request::PUT;     p += 4; }
  else if (strncmp(p, "DELETE ", 7) == 0) { req->method = Request::DELETE;  p += 7; }
  else if (strncmp(p, "HEAD ", 5) == 0)   { req->method = Request::HEAD;    p += 5; }
  else                                     { req->method = Request::UNKNOWN;         }

  int path_len = 0;
  while (*p && *p != ' ' && *p != '\r' && *p != '\n' &&
         path_len < (int)sizeof(req->path) - 1) {
    req->path[path_len++] = *p++;
  }
  req->path[path_len] = '\0';

  while (*p && *p != '\n') ++p;
  if (*p == '\n') ++p;

  // Parse header lines
  while (p < header_end) {
    if (*p == '\r' || *p == '\n')
      break;

    int ni = 0;
    if (req->header_count < 16) {
      char *hname = req->headers[req->header_count].name;
      char *hval  = req->headers[req->header_count].value;

      while (*p && *p != ':' && *p != '\r' && ni < 63)
        hname[ni++] = *p++;
      hname[ni] = '\0';

      while (*p == ':' || *p == ' ') ++p;

      int vi = 0;
      while (*p && *p != '\r' && *p != '\n' && vi < 255)
        hval[vi++] = *p++;
      hval[vi] = '\0';

      ++req->header_count;
    }

    while (*p && *p != '\n') ++p;
    if (*p == '\n') ++p;
  }

  const char *body_start = header_end + 4;
  size_t consumed = (size_t)(body_start - data);

  const char *cl = req->get_header("Content-Length");
  if (cl) {
    size_t body_len = 0;
    const char *q = cl;
    while (*q >= '0' && *q <= '9') {
      body_len = body_len * 10 + (*q - '0');
      ++q;
    }
    size_t avail = (size_t)(data + len - body_start);
    if (avail < body_len)
      return 0;
    if (body_len > sizeof(req->body) - 1)
      body_len = sizeof(req->body) - 1;
    memcpy(req->body, body_start, body_len);
    req->body_len = body_len;
    req->body[body_len] = '\0';
    consumed += body_len;
  }

  return consumed;
}

// ---- Response sender --------------------------------------------------------

void Server::send_response(uni::tcp::Connection *conn, const Response &resp,
                           bool keep_alive) const {
  size_t body_len = resp.body_len ? resp.body_len : strlen(resp.body);

  // Build headers + body in one buffer → single tcp::send → one TCP segment.
  char buf[2048];
  int len = 0;

  auto append = [&](const char *s, size_t n = 0) {
    if (n == 0) n = strlen(s);
    if (len + (int)n < (int)sizeof(buf)) {
      memcpy(buf + len, s, n);
      len += (int)n;
    }
  };

  append("HTTP/1.1 ");
  char num[12];
  fmt_int(num, sizeof(num), resp.status);
  append(num);
  append(" ");
  append(status_text(resp.status));
  append("\r\n");

  append("Content-Type: ");
  append(resp.content_type);
  append("\r\n");

  append("Content-Length: ");
  fmt_int(num, sizeof(num), (int)body_len);
  append(num);
  append("\r\n");

  append(keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n");
  append("\r\n");

  if (body_len > 0)
    append(resp.body, body_len);

  uni::tcp::send(conn, buf, (size_t)len);
}

// ---- Event loop -------------------------------------------------------------

void Server::run(uint16_t port_override) {
  uint16_t port = port_override ? port_override : port_;
  uni::tcp::Connection *listener = uni::tcp::listen(port);
  if (!listener) {
    uni::log("http: failed to create TCP listener on port %u\n",
                  (unsigned)port);
    return;
  }

  uni::log("http: listening on port %u\n", (unsigned)port);

  while (true) {
    if (uni::check_shutdown()) {
      uni::log("http: shutdown requested — stopping server.\n");
      break;
    }
    uni::tcp::poll();

    bool had_work = false;

    // ---- Accept new connections ----------------------------------------
    while (true) {
      uni::tcp::Connection *new_conn = uni::tcp::accept(listener);
      if (!new_conn)
        break;
      had_work = true;
      ActiveConn *ac = alloc_active();
      if (ac) {
        ac->conn = new_conn;
      } else {
        uni::log("http: too many connections, dropping\n");
        uni::tcp::close(new_conn);
        break;
      }
    }

    // ---- Service active connections ------------------------------------
    for (int i = 0; i < MAX_ACTIVE; ++i) {
      ActiveConn *ac = &active_[i];
      if (!ac->in_use || !ac->conn)
        continue;

      uni::tcp::Connection *conn = ac->conn;

      if (uni::tcp::is_closed(conn)) {
        free_active(ac);
        had_work = true;
        continue;
      }

      if (uni::tcp::has_data(conn)) {
        size_t avail = sizeof(ac->buf) - ac->buf_len;
        if (avail > 0) {
          size_t got = uni::tcp::recv(conn, ac->buf + ac->buf_len, avail);
          ac->buf_len += got;
          had_work = true;
        }
      }

      if (ac->buf_len > 0) {
        Request req;
        size_t consumed = parse_request(ac->buf, ac->buf_len, &req);
        if (consumed > 0) {
          const char *conn_hdr = req.get_header("Connection");
          bool want_close = conn_hdr && str_iequal(conn_hdr, "close");

          Handler h = find_handler(req.path);
          Response resp;
          if (h) {
            resp = h(req);
          } else {
            resp = Response::not_found();
          }

          send_response(conn, resp, !want_close);
          had_work = true;

          if (want_close) {
            uni::tcp::close(conn);
            free_active(ac);
          } else {
            size_t remaining = ac->buf_len - consumed;
            if (remaining > 0)
              memcpy(ac->buf, ac->buf + consumed, remaining);
            ac->buf_len = remaining;
          }
        } else if (ac->buf_len >= sizeof(ac->buf)) {
          uni::tcp::close(conn);
          free_active(ac);
        }
      }
    }

    if (!had_work) {
      uni::wait_for_events();
    }
  }

  // Graceful shutdown
  for (int i = 0; i < MAX_ACTIVE; ++i) {
    if (active_[i].in_use && active_[i].conn) {
      uni::tcp::close(active_[i].conn);
      free_active(&active_[i]);
    }
  }
  uni::tcp::close(listener);
  uni::log("http: server stopped.\n");
}

} // namespace http
} // namespace net
