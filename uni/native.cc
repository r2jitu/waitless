// uni/native.cc — uni:: implementation for the native host process.
//
// Uses POSIX sockets for TCP, fprintf(stderr) for logging, and SIGINT for
// shutdown detection.  Mirrors the same interface as uni/unikernel.cc so
// that the same HTTP server and application code can run on the host for
// benchmarking and debugging.

#include "uni/uni.h"

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

// ---- Connection pool ---------------------------------------------------------

struct uni::tcp::Connection {
  int fd = -1;
  bool is_listener = false;
  bool closed = true;
  bool has_pending_data = false;
};

static constexpr int CONN_POOL_SIZE = 256;
static uni::tcp::Connection g_pool[CONN_POOL_SIZE];

static uni::tcp::Connection *alloc_conn() {
  for (auto &c : g_pool) {
    if (c.closed && c.fd < 0) {
      c = uni::tcp::Connection{};
      c.closed = false;
      return &c;
    }
  }
  return nullptr;
}

static void release_conn(uni::tcp::Connection *c) {
  if (c->fd >= 0) {
    ::shutdown(c->fd, SHUT_RDWR);
    ::close(c->fd);
    c->fd = -1;
  }
  c->closed = true;
  c->has_pending_data = false;
  c->is_listener = false;
}

// ---- Configuration -----------------------------------------------------------

static uint16_t g_config_port = 0; // 0 = unset; see uni::config_port()

uint16_t uni::config_port(uint16_t default_port) {
  return g_config_port ? g_config_port : default_port;
}

// ---- Shutdown ----------------------------------------------------------------

static volatile bool g_shutdown = false;

static void sigint_handler(int) { g_shutdown = true; }

void uni::init_native() {
  // Read $PORT so that uni::config_port() works before uni_main() is called.
  if (const char *p = ::getenv("PORT"))
    g_config_port = static_cast<uint16_t>(::atoi(p));

  struct sigaction sa;
  sa.sa_handler = sigint_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
  // Ignore SIGPIPE so that writing to a closed socket returns EPIPE rather
  // than killing the process.
  signal(SIGPIPE, SIG_IGN);
}

[[noreturn]] void uni::shutdown() { ::exit(0); }

bool uni::check_shutdown() { return g_shutdown; }

// ---- Logging -----------------------------------------------------------------

void uni::log(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  ::vfprintf(stderr, fmt, ap);
  va_end(ap);
  ::fflush(stderr);
}

// ---- Idle (poll-based) -------------------------------------------------------

void uni::wait_for_events() {
  // Collect all open file descriptors.
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
    // No sockets open — yield briefly.
    struct timespec ts = {0, 1000000}; // 1 ms
    nanosleep(&ts, nullptr);
    return;
  }
  // Block up to 10 ms for any socket to become readable.
  ::poll(fds, n, 10);
  // Update has_pending_data flags.
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

// ---- TCP ---------------------------------------------------------------------

uni::tcp::Connection *uni::tcp::listen(uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    ::fprintf(stderr, "platform: socket() failed: %s\n", strerror(errno));
    return nullptr;
  }

  int opt = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  // Non-blocking so accept() returns immediately when no connection is ready.
  ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (::bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) <
      0) {
    ::fprintf(stderr, "platform: bind(:%u) failed: %s\n", port,
              strerror(errno));
    ::close(fd);
    return nullptr;
  }
  if (::listen(fd, 128) < 0) {
    ::fprintf(stderr, "platform: listen() failed: %s\n", strerror(errno));
    ::close(fd);
    return nullptr;
  }

  Connection *c = alloc_conn();
  if (!c) {
    ::fprintf(stderr, "platform: connection pool exhausted\n");
    ::close(fd);
    return nullptr;
  }
  c->fd = fd;
  c->is_listener = true;
  return c;
}

uni::tcp::Connection *uni::tcp::accept(Connection *listener) {
  if (!listener || listener->fd < 0 || listener->closed)
    return nullptr;

  int fd = ::accept(listener->fd, nullptr, nullptr);
  if (fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      listener->has_pending_data = false;
    return nullptr;
  }

  // Non-blocking so recv() returns immediately when no data is ready.
  ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

  Connection *c = alloc_conn();
  if (!c) {
    ::close(fd);
    return nullptr;
  }
  c->fd = fd;
  return c;
}

bool uni::tcp::has_data(Connection *conn) {
  if (!conn || conn->closed)
    return false;
  return conn->has_pending_data;
}

size_t uni::tcp::recv(Connection *conn, void *buf, size_t max_len) {
  if (!conn || conn->fd < 0 || conn->closed)
    return 0;
  ssize_t n = ::recv(conn->fd, buf, max_len, 0);
  if (n < 0) {
    conn->has_pending_data = false;
    return 0;
  }
  if (n == 0) {
    // EOF — remote closed the connection.
    conn->closed = true;
    conn->has_pending_data = false;
    return 0;
  }
  // Reset flag; poll() will re-set it if more data arrives.
  conn->has_pending_data = false;
  return static_cast<size_t>(n);
}

int uni::tcp::send(Connection *conn, const void *data, size_t len) {
  if (!conn || conn->fd < 0 || conn->closed)
    return -1;
  ssize_t sent = ::send(conn->fd, data, len, MSG_NOSIGNAL);
  if (sent < 0)
    return -1;
  return static_cast<int>(sent);
}

void uni::tcp::close(Connection *conn) {
  if (!conn)
    return;
  release_conn(conn);
}

void uni::tcp::poll() {
  // Non-blocking poll to update has_pending_data flags for all open sockets.
  struct pollfd fds[CONN_POOL_SIZE];
  uni::tcp::Connection *map[CONN_POOL_SIZE];
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
  ::poll(fds, n, 0); // non-blocking
  for (int i = 0; i < n; i++) {
    if (fds[i].revents & (POLLIN | POLLHUP | POLLERR))
      map[i]->has_pending_data = true;
  }
}

bool uni::tcp::is_closed(Connection *conn) {
  return !conn || conn->closed;
}
