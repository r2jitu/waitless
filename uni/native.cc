// uni/native.cc — Native (POSIX) backend: extern "C" functions for Rust interop
//
// Provides the same uni_* extern "C" symbols as ffi.cc, but implemented
// with POSIX sockets and stdio. The linker selects native.cc for the native
// binary and ffi.cc for the unikernel binary.

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdarg.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// ---- Connection pool --------------------------------------------------------

struct NativeConn {
  int fd = -1;
  bool is_listener = false;
  bool closed = true;
  bool has_pending_data = false;
};

static constexpr int CONN_POOL_SIZE = 256;
static NativeConn g_pool[CONN_POOL_SIZE];

static NativeConn *alloc_conn() {
  for (auto &c : g_pool) {
    if (c.closed && c.fd < 0) {
      c = NativeConn{};
      c.closed = false;
      return &c;
    }
  }
  return nullptr;
}

static void release_conn(NativeConn *c) {
  if (c->fd >= 0) {
    ::shutdown(c->fd, SHUT_RDWR);
    ::close(c->fd);
    c->fd = -1;
  }
  c->closed = true;
  c->has_pending_data = false;
  c->is_listener = false;
}

// ---- State ------------------------------------------------------------------

static uint16_t g_config_port = 0;
static volatile bool g_shutdown = false;

static void sigint_handler(int) { g_shutdown = true; }

// ---- Init (called by native_main.cc) ----------------------------------------

static void init_native() {
  if (const char *p = ::getenv("PORT"))
    g_config_port = static_cast<uint16_t>(::atoi(p));

  struct sigaction sa;
  sa.sa_handler = sigint_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
  signal(SIGPIPE, SIG_IGN);
}

// ---- Extern "C" API (same symbols as ffi.cc) --------------------------------

extern "C" {

void uni_init_native() { init_native(); }

void uni_log(const char *msg) {
  ::fprintf(stderr, "%s", msg);
  ::fflush(stderr);
}

uint16_t uni_config_port(uint16_t default_port) {
  return g_config_port ? g_config_port : default_port;
}

bool uni_check_shutdown() { return g_shutdown; }

void uni_wait_for_events() {
  struct pollfd fds[CONN_POOL_SIZE];
  int n = 0;
  for (auto &c : g_pool) {
    if (!c.closed && c.fd >= 0) {
      fds[n].fd = c.fd;
      fds[n].events = POLLIN;
      fds[n].revents = 0;
      n++;
    }
  }
  if (n == 0) {
    struct timespec ts = {0, 1000000}; // 1 ms
    nanosleep(&ts, nullptr);
    return;
  }
  ::poll(fds, n, 10);
  for (int i = 0; i < n; i++) {
    if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
      for (auto &c : g_pool) {
        if (c.fd == fds[i].fd) {
          c.has_pending_data = true;
          break;
        }
      }
    }
  }
}

// ---- TCP --------------------------------------------------------------------

void *uni_tcp_listen(uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return nullptr;

  int opt = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (::bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) <
      0) {
    ::close(fd);
    return nullptr;
  }
  if (::listen(fd, 128) < 0) {
    ::close(fd);
    return nullptr;
  }

  NativeConn *c = alloc_conn();
  if (!c) {
    ::close(fd);
    return nullptr;
  }
  c->fd = fd;
  c->is_listener = true;
  return static_cast<void *>(c);
}

void *uni_tcp_accept(void *conn) {
  auto *listener = static_cast<NativeConn *>(conn);
  if (!listener || listener->fd < 0 || listener->closed)
    return nullptr;

  int fd = ::accept(listener->fd, nullptr, nullptr);
  if (fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      listener->has_pending_data = false;
    return nullptr;
  }

  ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

  NativeConn *c = alloc_conn();
  if (!c) {
    ::close(fd);
    return nullptr;
  }
  c->fd = fd;
  return static_cast<void *>(c);
}

bool uni_tcp_has_data(void *conn) {
  auto *c = static_cast<NativeConn *>(conn);
  if (!c || c->closed)
    return false;
  return c->has_pending_data;
}

size_t uni_tcp_recv(void *conn, void *buf, size_t max_len) {
  auto *c = static_cast<NativeConn *>(conn);
  if (!c || c->fd < 0 || c->closed)
    return 0;
  ssize_t n = ::recv(c->fd, buf, max_len, 0);
  if (n < 0) {
    c->has_pending_data = false;
    return 0;
  }
  if (n == 0) {
    c->closed = true;
    c->has_pending_data = false;
    return 0;
  }
  c->has_pending_data = false;
  return static_cast<size_t>(n);
}

int uni_tcp_send(void *conn, const void *data, size_t len) {
  auto *c = static_cast<NativeConn *>(conn);
  if (!c || c->fd < 0 || c->closed)
    return -1;
  ssize_t sent = ::send(c->fd, data, len, MSG_NOSIGNAL);
  if (sent < 0)
    return -1;
  return static_cast<int>(sent);
}

void uni_tcp_close(void *conn) {
  auto *c = static_cast<NativeConn *>(conn);
  if (!c)
    return;
  release_conn(c);
}

bool uni_tcp_is_closed(void *conn) {
  auto *c = static_cast<NativeConn *>(conn);
  return !c || c->closed;
}

void uni_tcp_poll() {
  struct pollfd fds[CONN_POOL_SIZE];
  NativeConn *map[CONN_POOL_SIZE];
  int n = 0;
  for (auto &c : g_pool) {
    if (!c.closed && c.fd >= 0) {
      fds[n].fd = c.fd;
      fds[n].events = POLLIN;
      fds[n].revents = 0;
      map[n] = &c;
      n++;
    }
  }
  if (n == 0)
    return;
  ::poll(fds, n, 0);
  for (int i = 0; i < n; i++) {
    if (fds[i].revents & (POLLIN | POLLHUP | POLLERR))
      map[i]->has_pending_data = true;
  }
}

} // extern "C"
