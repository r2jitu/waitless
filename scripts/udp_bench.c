// scripts/udp_bench.c — High-performance UDP echo benchmark client.
//
// Two modes:
//   1. Sync mode (default): N sender processes, each doing synchronous
//      sendto/recvfrom. Measures round-trip latency and throughput.
//   2. Async mode (--async): single process, single thread. N
//      non-blocking sockets multiplexed via poll(). One loop drives
//      all sends (paced or blast) and drains all replies — no fork,
//      no pthread, no scheduler contention. Total client CPU is
//      one core (vs the old fork-per-sender design which used 2N
//      processes and scheduler-thrashed against the runner).
//
// Pacing:
//   --rate=PPS   Throttle each async sender to PPS packets/sec. The
//                aggregate offered load is `PPS * senders`. Without
//                a rate cap senders blast as fast as the loop can
//                send; the recv rate is then a measure of host-side
//                drop cascade more than steady-state server capacity,
//                so prefer paced runs for headline numbers.
//
// Client parallelism:
//   --client-cpus=N   Run async mode with N worker threads (default 1).
//                     Senders are partitioned evenly across threads.
//                     bench.py sets this to match the server's vCPU
//                     count so client and server get the same share of
//                     the host; without it a single-threaded bench can
//                     become the throughput ceiling at multi-core
//                     server configurations.
//
// Build: cc -O2 -o udp_bench scripts/udp_bench.c -lpthread
// Usage: udp_bench <port> <senders> <duration_sec> [--async] [--rate=PPS]
//                  [--client-cpus=N]
//
// Reports machine-readable RESULT line on stdout for bench.py, plus
// human-readable details on stderr.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
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

// ── Async multi-socket sender (single process, single thread) ────────────────
//
// All N senders run inside one event loop. Each sender owns a non-blocking
// UDP socket. The loop:
//   1. Computes how many packets *should* have been sent by now based on
//      monotonic clock and aggregate target rate.
//   2. Sends the deficit, distributing round-robin across sockets, capped
//      at 64 per cycle so recv doesn't starve.
//   3. poll()s all sockets (with a timeout sized to the next send deadline)
//      and drains everything readable.
// Total client cost: one CPU. The previous fork-per-sender design used 2N
// processes (N senders + N recv children) and on a 4c bench config left
// 16 client processes scheduler-thrashing with the runner — bench
// numbers were dominated by client/runner CPU contention rather than
// server throughput.

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static void drain_sockets(struct pollfd *pfds, int n_senders, long *received) {
    char rbuf[256];
    for (int i = 0; i < n_senders; i++) {
        if (!(pfds[i].revents & POLLIN)) continue;
        while (1) {
            ssize_t r = recv(pfds[i].fd, rbuf, sizeof(rbuf), 0);
            if (r <= 0) break;
            received[i]++;
        }
        pfds[i].revents = 0;
    }
}

/// Run async multi-sender benchmark in one process/thread.
/// `rate_pps` is per-sender (0 = blast). Writes per-sender counters
/// into `out_per_sender[0..n_senders]`.
static void run_async_multi(const char *host, int port, int duration,
                            int n_senders, long rate_pps,
                            struct result *out_per_sender) {
    struct sockaddr_in dst = {0};
    if (resolve_host(host, port, &dst) != 0) {
        fprintf(stderr, "resolve_host(%s) failed\n", host);
        return;
    }

    int *fds = calloc(n_senders, sizeof(int));
    long *sent = calloc(n_senders, sizeof(long));
    long *received = calloc(n_senders, sizeof(long));
    struct pollfd *pfds = calloc(n_senders, sizeof(struct pollfd));
    if (!fds || !sent || !received || !pfds) { perror("calloc"); return; }

    const int bufsz = 16 * 1024 * 1024;
    for (int i = 0; i < n_senders; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[i] < 0) { perror("socket"); return; }
        setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
        setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
        int flags = fcntl(fds[i], F_GETFL, 0);
        fcntl(fds[i], F_SETFL, flags | O_NONBLOCK);
        // Bind to ephemeral so each sender has a distinct source port —
        // that's what gives the runner's software RSS / KVM's tap RSS
        // something to hash on.
        struct sockaddr_in src = {0};
        src.sin_family = AF_INET;
        src.sin_port = 0;
        src.sin_addr.s_addr = htonl(INADDR_ANY);
        bind(fds[i], (struct sockaddr *)&src, sizeof(src));
        pfds[i].fd = fds[i];
        pfds[i].events = POLLIN;
    }

    const long total_rate = (rate_pps > 0) ? (long)rate_pps * n_senders : 0;
    const double start = now_us();
    const double end = start + (double)duration * 1e6;
    char sbuf[64] = "bench";
    long total_sent = 0;
    int rr = 0;

    while (1) {
        double now = now_us();
        if (now >= end) break;

        // Compute how many packets should have been sent by now.
        long target;
        if (total_rate > 0) {
            target = (long)((now - start) * (double)total_rate / 1e6);
        } else {
            // Blast mode: keep sending up to 64 per cycle, drain in between.
            target = total_sent + 64;
        }

        // Send the deficit, capped per cycle so we don't starve recv.
        int burst = 0;
        while (total_sent < target && burst < 64) {
            ssize_t r = sendto(fds[rr], sbuf, 5, 0,
                               (struct sockaddr *)&dst, sizeof(dst));
            if (r > 0) {
                sent[rr]++;
                total_sent++;
            } else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // Send buffer full on this socket; try the next one.
            }
            rr = (rr + 1) % n_senders;
            burst++;
        }

        // Compute poll timeout: how long until the next send is due, in ms.
        int timeout_ms = 0;
        if (total_rate > 0 && total_sent >= target) {
            double next_us = start + ((double)(total_sent + 1) * 1e6
                                       / (double)total_rate);
            double dt = next_us - now;
            if (dt > 1000.0) {
                timeout_ms = (int)(dt / 1000.0);
                if (timeout_ms > 50) timeout_ms = 50;
            }
        }

        if (poll(pfds, n_senders, timeout_ms) > 0) {
            drain_sockets(pfds, n_senders, received);
        }
    }

    // Final drain: wait up to ~100ms for in-flight replies.
    double drain_until = now_us() + 100000.0;
    while (now_us() < drain_until) {
        if (poll(pfds, n_senders, 10) > 0) {
            drain_sockets(pfds, n_senders, received);
        }
    }

    const double elapsed_s = (now_us() - start) / 1e6;
    for (int i = 0; i < n_senders; i++) {
        out_per_sender[i].count = received[i];
        out_per_sender[i].sent = sent[i];
        out_per_sender[i].elapsed = elapsed_s;
        memset(out_per_sender[i].buckets, 0, sizeof(out_per_sender[i].buckets));
        out_per_sender[i].overflow = 0;
        close(fds[i]);
    }
    free(pfds);
    free(received);
    free(sent);
    free(fds);
}

// ── Async pthread worker ─────────────────────────────────────────────────────

struct async_thread_args {
    const char *host;
    int port;
    int duration;
    int n_senders;
    long rate_pps;
    struct result *out;
};

static void *async_thread_entry(void *arg) {
    struct async_thread_args *a = arg;
    run_async_multi(a->host, a->port, a->duration, a->n_senders, a->rate_pps, a->out);
    return NULL;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: udp_bench <port> <senders> <duration_sec>"
            " [--async] [--host=IP] [--rate=PPS] [--client-cpus=N]\n");
        return 1;
    }
    int port = atoi(argv[1]);
    int senders = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int async_mode = 0;
    long rate_pps = 0; // 0 = no rate cap (blast)
    int client_cpus = 1;
    const char *host = "127.0.0.1";
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--async") == 0) async_mode = 1;
        else if (strncmp(argv[i], "--host=", 7) == 0) host = argv[i] + 7;
        else if (strncmp(argv[i], "--rate=", 7) == 0) rate_pps = atol(argv[i] + 7);
        else if (strncmp(argv[i], "--client-cpus=", 14) == 0) client_cpus = atoi(argv[i] + 14);
    }

    if (senders < 1 || senders > 64) {
        fprintf(stderr, "senders must be 1-64\n");
        return 1;
    }
    if (client_cpus < 1) client_cpus = 1;
    if (client_cpus > senders) client_cpus = senders;
    if (client_cpus > 32) client_cpus = 32;

    size_t shm_size = sizeof(struct result) * senders;
    struct result *results = mmap(NULL, shm_size,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (results == MAP_FAILED) { perror("mmap"); return 1; }
    memset(results, 0, shm_size);

    if (async_mode) {
        // Async mode: N pthread workers, senders partitioned across them.
        // At client_cpus=1 this collapses back to a single poll-multiplex
        // thread, matching the prior behaviour exactly.
        pthread_t tids[32];
        struct async_thread_args targs[32];
        int base = senders / client_cpus;
        int extra = senders % client_cpus;
        int offset = 0;
        int n_threads = 0;
        for (int t = 0; t < client_cpus; t++) {
            int n = base + (t < extra ? 1 : 0);
            if (n <= 0) continue;
            targs[n_threads] = (struct async_thread_args){
                .host = host,
                .port = port,
                .duration = duration,
                .n_senders = n,
                .rate_pps = rate_pps,
                .out = &results[offset],
            };
            if (pthread_create(&tids[n_threads], NULL,
                               async_thread_entry, &targs[n_threads]) != 0) {
                perror("pthread_create");
                // Run inline as fallback.
                run_async_multi(host, port, duration, n, rate_pps, &results[offset]);
            } else {
                n_threads++;
            }
            offset += n;
        }
        for (int t = 0; t < n_threads; t++) {
            pthread_join(tids[t], NULL);
        }
    } else {
        // Sync mode: fork-per-sender so each sender's blocking
        // sendto/recvfrom doesn't serialise with the others.
        pid_t pids[64];
        for (int i = 0; i < senders; i++) {
            pids[i] = fork();
            if (pids[i] == 0) {
                run_sync(host, port, duration, i == 0, &results[i]);
                _exit(0);
            }
        }
        for (int i = 0; i < senders; i++)
            waitpid(pids[i], NULL, 0);
    }

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
        // SENT line lets consumers compute delivery ratio directly
        // instead of re-deriving it from the --rate target. Printed
        // before RESULT so the parser sees both after one read.
        printf("SENT %.0f\n", send_rate);
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
