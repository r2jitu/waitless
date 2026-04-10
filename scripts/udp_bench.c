// scripts/udp_bench.c — High-performance UDP echo benchmark client.
//
// Two modes:
//   1. Sync mode (default): N sender processes, each doing synchronous
//      sendto/recvfrom. Measures round-trip latency and throughput.
//   2. Async mode (--async): separate send and recv threads per sender
//      process, pipelining sends without waiting for replies. Measures
//      maximum sustainable throughput and reply rate.
//
// Build: cc -O2 -o udp_bench scripts/udp_bench.c -lpthread
// Usage: udp_bench <port> <senders> <duration_sec> [--async]
//
// Reports machine-readable RESULT line on stdout for bench.py, plus
// human-readable details on stderr.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
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

// ── Sync sender ───────────────────────────────────────────────────────────────

static void run_sync(int port, int duration, int collect_lat,
                     struct result *out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

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

// ── Async sender (pipelined send + recv threads) ──────────────────────────────

struct async_ctx {
    int fd;
    volatile int stop;
    long received;
};

static void *async_recv_thread(void *arg) {
    struct async_ctx *c = arg;
    char rbuf[128];
    while (!c->stop) {
        ssize_t r = recv(c->fd, rbuf, sizeof(rbuf), 0);
        if (r > 0) __atomic_add_fetch(&c->received, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

static void run_async(int port, int duration, struct result *out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    int bufsz = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));

    struct timeval tv = {0, 10000}; // 10ms recv timeout for the recv thread
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct async_ctx ctx = { .fd = fd, .stop = 0, .received = 0 };
    pthread_t rthr;
    pthread_create(&rthr, NULL, async_recv_thread, &ctx);

    char buf[64] = "bench";
    long sent = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    double end = t0.tv_sec + t0.tv_nsec / 1e9 + duration;

    while (1) {
        sendto(fd, buf, 5, 0, (struct sockaddr *)&dst, sizeof(dst));
        sent++;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (t1.tv_sec + t1.tv_nsec / 1e9 >= end) break;
    }

    // Let replies drain for 100ms.
    usleep(100000);
    ctx.stop = 1;
    pthread_join(rthr, NULL);

    out->elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    out->sent = sent;
    out->count = ctx.received;
    memset(out->buckets, 0, sizeof(out->buckets));
    out->overflow = 0;
    close(fd);
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: udp_bench <port> <senders> <duration_sec> [--async]\n");
        return 1;
    }
    int port = atoi(argv[1]);
    int senders = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int async_mode = argc > 4 && strcmp(argv[4], "--async") == 0;

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
                run_async(port, duration, &results[i]);
            else
                run_sync(port, duration, i == 0, &results[i]);
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
