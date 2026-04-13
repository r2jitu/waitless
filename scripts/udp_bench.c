// scripts/udp_bench.c — High-performance UDP echo benchmark client.
//
// Two modes:
//   1. Sync mode (default): N sender processes, each doing synchronous
//      sendto/recvfrom. Measures round-trip latency and throughput.
//   2. Async mode (--async): each sender process forks a child that
//      does the blocking recv() loop, while the parent blasts sendto()
//      in a tight loop. Split across processes so the send loop can't
//      starve the recv loop on one CPU — the old single-process
//      pthread model capped at ~75k recv/s because the send thread
//      held a core and recvmsg() timed out for replies it could have
//      drained if it had gotten scheduled. Shared memory carries the
//      counters back to the parent.
//
// Pacing:
//   --rate=PPS   Throttle each async sender to PPS packets/sec. Models
//                realistic concurrency: many clients each at a sustainable
//                rate rather than a few blasting the server to oblivion.
//                Without a rate cap the sender floods the runner and
//                huge numbers of packets are dropped at the RX ring,
//                making the reported recv rate a measure of overflow
//                loss instead of steady-state server throughput.
//
// Build: cc -O2 -o udp_bench scripts/udp_bench.c -lpthread
// Usage: udp_bench <port> <senders> <duration_sec> [--async] [--rate=PPS]
//
// Reports machine-readable RESULT line on stdout for bench.py, plus
// human-readable details on stderr.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// ── Latency histogram ─────────────────────────────────────────────────────────

#define HIST_BUCKETS 10001 // 0..10000µs; overflow tracked separately

struct result {
    long count;         // packets received
    long sent;          // packets sent (async mode)
    double elapsed;
    long buckets[HIST_BUCKETS];
    long overflow;
};

static long percentile(struct result *r, double pct) {
    long target = (long)(r->count * pct / 100.0);
    long cum = 0;
    for (int i = 0; i < HIST_BUCKETS; i++) {
        cum += r->buckets[i];
        if (cum >= target) return i;
    }
    return HIST_BUCKETS;
}

// Resolve a host (hostname or dotted-quad) to an IPv4 sockaddr_in. Returns
// 0 on success. inet_pton() alone silently leaves sin_addr = 0.0.0.0 for
// hostnames like "localhost", so we always go through getaddrinfo.
static int resolve_host(const char *host, int port, struct sockaddr_in *out) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || !res) return -1;
    memcpy(out, res->ai_addr, sizeof(*out));
    out->sin_port = htons(port);
    freeaddrinfo(res);
    return 0;
}

// ── Sync sender ───────────────────────────────────────────────────────────────

static void run_sync(const char *host, int port, int duration, int collect_lat,
                     struct result *out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst = {0};
    if (resolve_host(host, port, &dst) != 0) {
        fprintf(stderr, "resolve_host(%s) failed\n", host);
        close(fd);
        return;
    }

    struct timeval tv = {0, 50000}; // 50ms timeout
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[64] = "bench";
    char rbuf[128];
    long count = 0;
    memset(out->buckets, 0, sizeof(out->buckets));
    out->overflow = 0;

    struct timespec t0, t1, ps, pe;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    double end = t0.tv_sec + t0.tv_nsec / 1e9 + duration;

    while (1) {
        if (collect_lat) clock_gettime(CLOCK_MONOTONIC, &ps);
        sendto(fd, buf, 5, 0, (struct sockaddr *)&dst, sizeof(dst));
        ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
        if (r > 0) {
            count++;
            if (collect_lat) {
                clock_gettime(CLOCK_MONOTONIC, &pe);
                long us = ((pe.tv_sec - ps.tv_sec) * 1000000000L +
                           (pe.tv_nsec - ps.tv_nsec)) / 1000;
                if (us < HIST_BUCKETS) out->buckets[us]++;
                else out->overflow++;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (t1.tv_sec + t1.tv_nsec / 1e9 >= end) break;
    }
    out->elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    out->count = count;
    out->sent = count; // sync: sent == received (modulo timeouts)
    close(fd);
}

// ── Async sender (pipelined: send process + recv child process) ──────────────
//
// The previous design ran send and recv as two pthreads in one process. On
// loopback, sendto() at 300k+ pps CPU-binds the send thread so thoroughly
// that the recv thread rarely gets a scheduler slice — which manifests as
// recv() blocking past the recv timeout and reporting far fewer replies
// than were actually delivered. Splitting the recv loop into a child
// process gives it its own CPU and eliminates the starvation.

/// Async child: drains replies in a tight blocking recv loop. Writes the
/// running count into shared memory so the parent can read it. Exits when
/// it sees SIGUSR1 from the parent (parent raises it after the send loop
/// finishes and the reply buffer is drained).
static volatile sig_atomic_t g_stop_recv = 0;
static void async_recv_sigusr1(int _sig) { (void)_sig; g_stop_recv = 1; }

static void async_recv_child(int fd, _Atomic long *received_out) {
    struct sigaction sa = {0};
    sa.sa_handler = async_recv_sigusr1;
    sigaction(SIGUSR1, &sa, NULL);
    char rbuf[256];
    while (!g_stop_recv) {
        ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
        if (r > 0) {
            atomic_fetch_add_explicit(received_out, 1, memory_order_relaxed);
        } else if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
    }
    _exit(0);
}

static void run_async(const char *host, int port, int duration, long rate_pps,
                      struct result *out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst = {0};
    if (resolve_host(host, port, &dst) != 0) {
        fprintf(stderr, "resolve_host(%s) failed\n", host);
        close(fd);
        return;
    }

    // Big socket buffers so bursts don't drop at either the send-queue
    // egress or the reply ingress. 16 MB is ~100ms of 1500-byte packets
    // at 100k pps, giving the drain loop room to breathe.
    int bufsz = 16 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));

    // Shared-memory counter the child writes to. We use _Atomic long so
    // both processes see consistent updates without any extra locking.
    _Atomic long *received = mmap(NULL, sizeof(_Atomic long),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (received == MAP_FAILED) { perror("mmap(recv counter)"); close(fd); return; }
    atomic_store_explicit(received, 0, memory_order_relaxed);

    pid_t recv_pid = fork();
    if (recv_pid == 0) {
        async_recv_child(fd, received);
        _exit(0);
    }

    char buf[64] = "bench";
    long sent = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    double t0_s = t0.tv_sec + t0.tv_nsec / 1e9;
    double end = t0_s + duration;
    // Nanoseconds per packet when pacing is enabled. rate_pps <= 0 → no cap.
    const double ns_per_pkt = (rate_pps > 0) ? (1e9 / (double)rate_pps) : 0.0;

    while (1) {
        sendto(fd, buf, 5, 0, (struct sockaddr *)&dst, sizeof(dst));
        sent++;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double now_s = t1.tv_sec + t1.tv_nsec / 1e9;
        if (now_s >= end) break;
        if (ns_per_pkt > 0.0) {
            // Target time for packet N+1 = t0 + (N+1) * ns_per_pkt. If we're
            // ahead of schedule, sleep; if we're behind, keep going.
            double target = t0_s + ((double)(sent + 1)) * ns_per_pkt / 1e9;
            double delta_s = target - now_s;
            if (delta_s > 0.0) {
                if (delta_s > 0.001) usleep((useconds_t)(delta_s * 1e6));
                // For sub-ms sleeps, busy-wait to hit the target more exactly.
                else while (1) {
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    double s = ts.tv_sec + ts.tv_nsec / 1e9;
                    if (s >= target) break;
                }
            }
        }
    }

    // Let replies drain, then stop the child.
    usleep(100000);
    kill(recv_pid, SIGUSR1);
    int status;
    waitpid(recv_pid, &status, 0);

    out->elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    out->sent = sent;
    out->count = atomic_load_explicit(received, memory_order_relaxed);
    memset(out->buckets, 0, sizeof(out->buckets));
    out->overflow = 0;
    munmap((void *)received, sizeof(_Atomic long));
    close(fd);
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: udp_bench <port> <senders> <duration_sec>"
            " [--async] [--host=IP] [--rate=PPS]\n");
        return 1;
    }
    int port = atoi(argv[1]);
    int senders = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int async_mode = 0;
    long rate_pps = 0; // 0 = no rate cap (blast)
    const char *host = "127.0.0.1";
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--async") == 0) async_mode = 1;
        else if (strncmp(argv[i], "--host=", 7) == 0) host = argv[i] + 7;
        else if (strncmp(argv[i], "--rate=", 7) == 0) rate_pps = atol(argv[i] + 7);
    }

    if (senders < 1 || senders > 64) {
        fprintf(stderr, "senders must be 1-64\n");
        return 1;
    }

    size_t shm_size = sizeof(struct result) * senders;
    struct result *results = mmap(NULL, shm_size,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (results == MAP_FAILED) { perror("mmap"); return 1; }
    memset(results, 0, shm_size);

    pid_t pids[64];
    for (int i = 0; i < senders; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            if (async_mode)
                run_async(host, port, duration, rate_pps, &results[i]);
            else
                run_sync(host, port, duration, i == 0, &results[i]);
            _exit(0);
        }
    }
    for (int i = 0; i < senders; i++)
        waitpid(pids[i], NULL, 0);

    long total_recv = 0, total_sent = 0;
    double max_elapsed = 0;
    for (int i = 0; i < senders; i++) {
        total_recv += results[i].count;
        total_sent += results[i].sent;
        if (results[i].elapsed > max_elapsed)
            max_elapsed = results[i].elapsed;
    }

    double pps = total_recv / max_elapsed;
    struct result *lat = &results[0];
    long p50 = percentile(lat, 50);
    long p99 = percentile(lat, 99);
    long p999 = percentile(lat, 99.9);

    if (async_mode) {
        double send_rate = total_sent / max_elapsed;
        printf("RESULT %.0f %ld %ld %ld\n", pps, p50, p99, p999);
        fprintf(stderr, "UDP echo (async): %d sender(s), %ds\n",
                senders, duration);
        fprintf(stderr, "  Send rate:  %.0f pkt/s\n", send_rate);
        fprintf(stderr, "  Recv rate:  %.0f pkt/s (%.0f%% reply)\n",
                pps, 100.0 * total_recv / (total_sent ? total_sent : 1));
    } else {
        printf("RESULT %.0f %ld %ld %ld\n", pps, p50, p99, p999);
        fprintf(stderr, "UDP echo (sync): %d sender(s), %ds\n",
                senders, duration);
        fprintf(stderr, "  Throughput: %.0f pkt/s\n", pps);
        if (lat->count > 0) {
            fprintf(stderr, "  Latency (sender 0, %ld samples):\n",
                    lat->count);
            fprintf(stderr, "    p50  = %ldus\n", p50);
            fprintf(stderr, "    p90  = %ldus\n", percentile(lat, 90));
            fprintf(stderr, "    p99  = %ldus\n", p99);
            fprintf(stderr, "    p99.9= %ldus\n", p999);
            fprintf(stderr, "    max  = %ldus+ (%ld overflow)\n",
                    (long)HIST_BUCKETS - 1, lat->overflow);
        }
    }

    munmap(results, shm_size);
    return 0;
}
