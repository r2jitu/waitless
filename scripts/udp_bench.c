// scripts/udp_bench.c — High-performance UDP echo benchmark client.
//
// Spawns N sender processes, each doing synchronous sendto/recvfrom
// in a tight loop for a fixed duration. Reports aggregate throughput
// and per-packet latency percentiles from the first sender.
//
// Build: cc -O2 -o udp_bench scripts/udp_bench.c
// Usage: udp_bench <port> <senders> <duration_sec>
//
// Replaces the Python-based run_udp in bench.py, which was GIL-limited
// to ~50k pkt/s regardless of concurrency.

#include <arpa/inet.h>
#include <math.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Shared memory for child results (via mmap).
#include <sys/mman.h>

struct result {
    long count;
    double elapsed;
    // Latency histogram: buckets[i] = count of RTTs in [i*1µs, (i+1)*1µs)
    // Max bucket = 10000 = 10ms. Anything above goes in overflow.
    #define HIST_BUCKETS 10001
    long buckets[HIST_BUCKETS];
    long overflow;
};

static void run_sender(int port, int duration, int collect_latency,
                        struct result *out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);

    // 50ms recv timeout — long enough for any reasonable RTT, short
    // enough to not stall the benchmark if the server drops a packet.
    struct timeval tv = {0, 50000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[64] = "bench";
    char rbuf[128];
    long count = 0;

    memset(out->buckets, 0, sizeof(out->buckets));
    out->overflow = 0;

    struct timespec t0, t1, pkt_start, pkt_end;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    double end_time = t0.tv_sec + t0.tv_nsec / 1e9 + duration;

    while (1) {
        if (collect_latency)
            clock_gettime(CLOCK_MONOTONIC, &pkt_start);

        sendto(fd, buf, 5, 0, (struct sockaddr *)&dst, sizeof(dst));
        ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
        if (r > 0) {
            count++;
            if (collect_latency) {
                clock_gettime(CLOCK_MONOTONIC, &pkt_end);
                long ns = (pkt_end.tv_sec - pkt_start.tv_sec) * 1000000000L +
                          (pkt_end.tv_nsec - pkt_start.tv_nsec);
                long us = ns / 1000;
                if (us < HIST_BUCKETS)
                    out->buckets[us]++;
                else
                    out->overflow++;
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (t1.tv_sec + t1.tv_nsec / 1e9 >= end_time)
            break;
    }

    out->elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    out->count = count;
    close(fd);
}

static long percentile(struct result *r, double pct) {
    long target = (long)(r->count * pct / 100.0);
    long cum = 0;
    for (int i = 0; i < HIST_BUCKETS; i++) {
        cum += r->buckets[i];
        if (cum >= target) return i;
    }
    return HIST_BUCKETS; // overflow
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: udp_bench <port> <senders> <duration_sec>\n");
        return 1;
    }
    int port = atoi(argv[1]);
    int senders = atoi(argv[2]);
    int duration = atoi(argv[3]);

    if (senders < 1 || senders > 64) {
        fprintf(stderr, "senders must be 1-64\n");
        return 1;
    }

    // Allocate shared memory for child results.
    size_t shm_size = sizeof(struct result) * senders;
    struct result *results = mmap(NULL, shm_size,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (results == MAP_FAILED) { perror("mmap"); return 1; }
    memset(results, 0, shm_size);

    // Fork sender processes.
    pid_t pids[64];
    for (int i = 0; i < senders; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            // Child: run sender. Only sender 0 collects latency histogram
            // (to avoid the clock_gettime overhead on other senders).
            run_sender(port, duration, i == 0, &results[i]);
            _exit(0);
        }
    }

    // Wait for all children.
    for (int i = 0; i < senders; i++)
        waitpid(pids[i], NULL, 0);

    // Aggregate results.
    long total_count = 0;
    double max_elapsed = 0;
    for (int i = 0; i < senders; i++) {
        total_count += results[i].count;
        if (results[i].elapsed > max_elapsed)
            max_elapsed = results[i].elapsed;
    }

    double pps = total_count / max_elapsed;

    // Print machine-readable line for bench.py, then human-readable details.
    // Machine format: RESULT <pps> <p50_us> <p99_us> <p999_us>
    struct result *lat = &results[0];
    long p50 = percentile(lat, 50);
    long p99 = percentile(lat, 99);
    long p999 = percentile(lat, 99.9);

    printf("RESULT %.0f %ld %ld %ld\n", pps, p50, p99, p999);

    // Human-readable summary to stderr.
    fprintf(stderr, "UDP echo: %d sender(s), %ds\n", senders, duration);
    fprintf(stderr, "  Total: %.0f pkt/s\n", pps);
    fprintf(stderr, "  Latency (sender 0, %ld samples):\n", lat->count);
    fprintf(stderr, "    p50  = %ldus\n", p50);
    fprintf(stderr, "    p90  = %ldus\n", percentile(lat, 90));
    fprintf(stderr, "    p99  = %ldus\n", p99);
    fprintf(stderr, "    p99.9= %ldus\n", p999);
    fprintf(stderr, "    max  = %ldus+ (%ld overflow)\n",
            (long)HIST_BUCKETS - 1, lat->overflow);

    munmap(results, shm_size);
    return 0;
}
