/* bench/bench_server.c
 * Minimal poll()-based HTTP/1.1 server for benchmarking.
 *
 * Mirrors the unikernel's cooperative non-blocking design:
 *   - Single thread with a poll() event loop
 *   - Up to MAX_CLIENTS simultaneous connections (same as unikernel MAX_ACTIVE)
 *   - HTTP/1.1 keep-alive by default (matches unikernel behavior)
 *
 * This lets all three benchmark scenarios (unikernel, Linux/Docker, macOS)
 * run the same server logic so the OS/virtualization overhead is isolated.
 *
 * Build:
 *   Linux:  cc -O2 -DRUNTIME='"linux"' -o bench_server bench_server.c
 *   macOS:  cc -O2 -DRUNTIME='"macos"' -o bench_server bench_server.c
 * Usage:
 *   ./bench_server [port]   (default: 80)
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef RUNTIME
#define RUNTIME "native"
#endif

#define MAX_CLIENTS 64
#define BUF_SIZE 4096
#define BACKLOG 256

/* Check if the request contains "Connection: close" (case-insensitive). */
static int wants_close(const char *buf) {
  /* Simple scan for "connection: close" ignoring case. */
  const char *p = buf;
  while (*p) {
    if ((*p == 'C' || *p == 'c') &&
        strncasecmp(p, "connection: close", 17) == 0)
      return 1;
    p++;
  }
  return 0;
}

static int send_response(int fd, const char *buf) {
  char body[128];
  snprintf(body, sizeof(body),
           "{\"status\":\"ok\",\"runtime\":\"%s\",\"version\":\"0.1.0\"}",
           RUNTIME);
  int body_len = (int)strlen(body);

  int do_close = wants_close(buf);
  const char *conn_hdr = do_close ? "Connection: close" : "Connection: keep-alive";

  char resp[512];
  int resp_len;

  if (strncmp(buf, "GET /health", 11) == 0 || strncmp(buf, "GET / ", 6) == 0) {
    resp_len = snprintf(resp, sizeof(resp),
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %d\r\n"
                        "%s\r\n"
                        "\r\n"
                        "%s",
                        body_len, conn_hdr, body);
  } else {
    resp_len = snprintf(resp, sizeof(resp),
                        "HTTP/1.1 404 Not Found\r\n"
                        "Content-Type: text/plain\r\n"
                        "Content-Length: 13\r\n"
                        "%s\r\n"
                        "\r\n"
                        "404 Not Found",
                        conn_hdr);
  }

  send(fd, resp, (size_t)resp_len, 0);
  return do_close;
}

/* Remove slot i from the poll set by swapping with the last entry. */
static void remove_slot(struct pollfd *fds, int *buf_lens, int *nfds, int i) {
  close(fds[i].fd);
  int ci = i - 1;
  (*nfds)--;
  fds[i] = fds[*nfds];
  buf_lens[ci] = buf_lens[*nfds - 1];
  buf_lens[*nfds - 1] = 0;
}

int main(int argc, char *argv[]) {
  int port = 80;
  if (argc > 1)
    port = atoi(argv[1]);

  signal(SIGPIPE, SIG_IGN);

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) {
    perror("socket");
    return 1;
  }

  int opt = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((unsigned short)port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }
  if (listen(srv, BACKLOG) < 0) {
    perror("listen");
    return 1;
  }

  printf("bench_server [%s] on port %d\n", RUNTIME, port);
  fflush(stdout);

  /*
   * fds[0]         = listener socket
   * fds[1..nfds)   = active client connections
   * bufs[i-1]      = receive buffer for fds[i]
   * buf_lens[i-1]  = bytes accumulated in bufs[i-1]
   */
  struct pollfd fds[MAX_CLIENTS + 1];
  char bufs[MAX_CLIENTS][BUF_SIZE];
  int buf_lens[MAX_CLIENTS];

  fds[0].fd = srv;
  fds[0].events = POLLIN;
  int nfds = 1;
  memset(buf_lens, 0, sizeof(buf_lens));

  for (;;) {
    int ready = poll(fds, (unsigned int)nfds, -1);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      perror("poll");
      break;
    }

    /* Accept new connections */
    if (fds[0].revents & POLLIN) {
      int cli = accept(srv, NULL, NULL);
      if (cli >= 0) {
        if (nfds < MAX_CLIENTS + 1) {
          int one = 1;
          setsockopt(cli, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
          fds[nfds].fd = cli;
          fds[nfds].events = POLLIN;
          buf_lens[nfds - 1] = 0;
          nfds++;
        } else {
          close(cli); /* at capacity */
        }
      }
    }

    /*
     * Service active connections — iterate from the end so that
     * compacting the array (swap-with-last) is safe within the loop.
     */
    for (int i = nfds - 1; i >= 1; i--) {
      if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
        continue;

      int ci = i - 1; /* buffer index for this fd slot */

      ssize_t n = recv(fds[i].fd, bufs[ci] + buf_lens[ci],
                       (size_t)(BUF_SIZE - buf_lens[ci] - 1), 0);
      if (n <= 0) {
        remove_slot(fds, buf_lens, &nfds, i);
        continue;
      }

      buf_lens[ci] += (int)n;
      bufs[ci][buf_lens[ci]] = '\0';

      /* Check for complete request (headers terminated by \r\n\r\n). */
      char *end = strstr(bufs[ci], "\r\n\r\n");
      if (!end)
        continue;

      int do_close = send_response(fds[i].fd, bufs[ci]);
      if (do_close) {
        remove_slot(fds, buf_lens, &nfds, i);
      } else {
        /* Keep-alive: consume the processed request, keep leftover data. */
        char *next = end + 4;
        int remaining = buf_lens[ci] - (int)(next - bufs[ci]);
        if (remaining > 0)
          memmove(bufs[ci], next, (size_t)remaining);
        buf_lens[ci] = remaining;
      }
    }
  }

  close(srv);
  return 0;
}
