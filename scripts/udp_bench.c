// scripts/udp_bench.c — High-performance UDP echo benchmark client.
//
// Three modes:
//   1. Sync mode (default): N sender processes, each doing synchronous
//      sendto/recvfrom. Measures round-trip latency and throughput.
//   2. Async mode (--async): single process, single thread. N
//      non-blocking sockets multiplexed via poll(). One loop drives
//      all sends (paced or blast) and drains all replies — no fork,
//      no pthread, no scheduler contention. Total client CPU is
//      one core (vs the old fork-per-sender design which used 2N
//      processes and scheduler-thrashed against the runner).
//   3. Concurrent mode (--concurrent): T pthread workers, each
//      maintains N nonblocking UDP sockets with a fixed in-flight
//      window. Each slot fires the next request only after its
//      previous reply arrives or its timeout expires (default 100ms).
//      Total in-flight = N * T. Throughput is server-driven; there's
//      no rate to tune, no binary search. Each slot has its own
//      ephemeral source port → kernel SO_REUSEPORT distribution sees
//      different 4-tuples and spreads the load across server siblings
//      naturally. The headline metric is recv_rate; loss% is
//      reported alongside so a saturated server is visible.
//
// Pacing (--async only):
//   --rate=PPS   Throttle each async sender to PPS packets/sec. The
//                aggregate offered load is `PPS * senders`. Without
//                a rate cap senders blast as fast as the loop can
//                send; the recv rate is then a measure of host-side
//                drop cascade more than steady-state server capacity,
//                so prefer paced runs for headline numbers.
//
// Client parallelism:
//   --client-cpus=N   Worker thread count (default 1). For --async,
//                     senders are partitioned evenly across threads.
//                     For --concurrent, EACH thread gets `senders`
//                     slots — total in-flight is `senders * N`.
//                     bench.py sets this to match the server's vCPU
//                     count so the client's CPU budget scales with
//                     the server under test.
//
// Build: cc -O2 -o udp_bench scripts/udp_bench.c -lpthread
// Usage: udp_bench <port> <senders> <duration_sec>
//                  [--async] [--concurrent] [--host=IP]
//                  [--rate=PPS] [--client-cpus=N] [--timeout=MS]
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
    long sent;          // packets sent (async / concurrent modes)
    long lost;          // requests timed out without a reply (concurrent mode)
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

// ── Concurrent (windowed) sender ─────────────────────────────────────────────
//
// Maintains `n_slots` in-flight UDP requests, each on its own
// nonblocking socket bound to a distinct ephemeral source port. A
// slot fires the next request only after its previous reply arrives
// or its `timeout_us` expires. Throughput is server-driven: if the
// server is fast, slots cycle quickly; if it's saturated, slots back
// up and recv_rate plateaus at the server's real capacity.
//
// Per-slot state lives in two parallel arrays keyed by slot index:
//   `outstanding[i]`  — true if a request was sent and we're waiting
//                       for the reply or the timeout, whichever first
//   `send_time_us[i]` — monotonic timestamp when the current request
//                       was sent (0 when the slot is idle)
//
// Each iteration of the loop:
//   1. Computes a poll timeout = (next-due-timeout - now), so we
//      wake exactly when the earliest in-flight slot is ready to
//      either retire or be declared lost.
//   2. Fires sends on every idle slot (catching slots that finished
//      a reply in the previous drain pass).
//   3. poll(); for each ready socket recv() and stamp recv time.
//   4. Walks slots and times out any whose deadline has passed.
//
// Latency (RTT) is recorded into `out->buckets` for replies that
// arrive before timeout. Lost requests are not bucketed.
static void run_concurrent(const char *host, int port, int duration,
                           int n_slots, long timeout_us,
                           struct result *out) {
    struct sockaddr_in dst = {0};
    if (resolve_host(host, port, &dst) != 0) {
        fprintf(stderr, "resolve_host(%s) failed\n", host);
        return;
    }

    int *fds = calloc(n_slots, sizeof(int));
    int *outstanding = calloc(n_slots, sizeof(int));
    double *send_time_us = calloc(n_slots, sizeof(double));
    struct pollfd *pfds = calloc(n_slots, sizeof(struct pollfd));
    if (!fds || !outstanding || !send_time_us || !pfds) {
        perror("calloc"); return;
    }

    const int bufsz = 4 * 1024 * 1024;
    for (int i = 0; i < n_slots; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[i] < 0) { perror("socket"); return; }
        setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
        setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
        int flags = fcntl(fds[i], F_GETFL, 0);
        fcntl(fds[i], F_SETFL, flags | O_NONBLOCK);
        // Bind to ephemeral so each slot has a distinct source port.
        // The server's per-vCPU SO_REUSEPORT siblings hash the 4-tuple
        // and route different src_ports to different siblings; that's
        // what makes a "concurrent N clients" model exercise multi-core.
        struct sockaddr_in src = {0};
        src.sin_family = AF_INET;
        src.sin_port = 0;
        src.sin_addr.s_addr = htonl(INADDR_ANY);
        bind(fds[i], (struct sockaddr *)&src, sizeof(src));
        pfds[i].fd = fds[i];
        pfds[i].events = POLLIN;
    }

    char sbuf[64] = "bench";
    char rbuf[256];

    long total_sent = 0, total_recv = 0, total_lost = 0;
    memset(out->buckets, 0, sizeof(out->buckets));
    out->overflow = 0;

    const double start = now_us();
    const double end = start + (double)duration * 1e6;

    while (1) {
        double now = now_us();
        if (now >= end) break;

        // Fire sends on every idle slot.
        for (int i = 0; i < n_slots; i++) {
            if (outstanding[i]) continue;
            ssize_t r = sendto(fds[i], sbuf, 5, 0,
                               (struct sockaddr *)&dst, sizeof(dst));
            if (r > 0) {
                outstanding[i] = 1;
                send_time_us[i] = now;
                total_sent++;
            }
        }

        // Compute poll timeout: wake when the earliest outstanding
        // slot would time out. If all slots are idle (shouldn't
        // happen since we just fired) or already past deadline, use
        // 0 (non-blocking poll).
        double earliest_deadline = end;
        for (int i = 0; i < n_slots; i++) {
            if (!outstanding[i]) continue;
            double dl = send_time_us[i] + (double)timeout_us;
            if (dl < earliest_deadline) earliest_deadline = dl;
        }
        double dt_us = earliest_deadline - now;
        int timeout_ms;
        if (dt_us <= 0) {
            timeout_ms = 0;
        } else if (dt_us > 50000.0) {
            timeout_ms = 50;
        } else {
            timeout_ms = (int)(dt_us / 1000.0);
            if (timeout_ms < 1) timeout_ms = 1;
        }

        int p = poll(pfds, n_slots, timeout_ms);
        double after_poll = now_us();
        if (p > 0) {
            for (int i = 0; i < n_slots; i++) {
                if (!(pfds[i].revents & POLLIN)) continue;
                pfds[i].revents = 0;
                while (1) {
                    ssize_t r = recv(fds[i], rbuf, sizeof(rbuf), 0);
                    if (r <= 0) break;
                    if (outstanding[i]) {
                        long us = (long)(after_poll - send_time_us[i]);
                        if (us >= 0 && us < HIST_BUCKETS) {
                            out->buckets[us]++;
                        } else {
                            out->overflow++;
                        }
                        outstanding[i] = 0;
                        total_recv++;
                    }
                }
            }
        }

        // Sweep timeouts.
        double tnow = now_us();
        for (int i = 0; i < n_slots; i++) {
            if (!outstanding[i]) continue;
            if (tnow - send_time_us[i] > (double)timeout_us) {
                outstanding[i] = 0;
                total_lost++;
            }
        }
    }

    // Final drain window: collect replies for in-flight slots so we
    // don't double-count them as lost. Bounded so a stuck server can't
    // hang the bench.
    double drain_until = now_us() + 50000.0;
    while (now_us() < drain_until) {
        if (poll(pfds, n_slots, 5) <= 0) continue;
        double after_poll = now_us();
        for (int i = 0; i < n_slots; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;
            pfds[i].revents = 0;
            while (1) {
                ssize_t r = recv(fds[i], rbuf, sizeof(rbuf), 0);
                if (r <= 0) break;
                if (outstanding[i]) {
                    long us = (long)(after_poll - send_time_us[i]);
                    if (us >= 0 && us < HIST_BUCKETS) out->buckets[us]++;
                    else out->overflow++;
                    outstanding[i] = 0;
                    total_recv++;
                }
            }
        }
    }
    // Anything still outstanding after the drain window is lost.
    for (int i = 0; i < n_slots; i++) {
        if (outstanding[i]) total_lost++;
    }

    out->elapsed = (now_us() - start) / 1e6;
    out->count = total_recv;
    out->sent = total_sent;
    out->lost = total_lost;

    for (int i = 0; i < n_slots; i++) close(fds[i]);
    free(pfds);
    free(send_time_us);
    free(outstanding);
    free(fds);
}

struct concurrent_thread_args {
    const char *host;
    int port;
    int duration;
    int n_slots;
    long timeout_us;
    struct result *out;
};

static void *concurrent_thread_entry(void *arg) {
    struct concurrent_thread_args *a = arg;
    run_concurrent(a->host, a->port, a->duration, a->n_slots, a->timeout_us, a->out);
    return NULL;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: udp_bench <port> <senders> <duration_sec>"
            " [--async] [--concurrent] [--host=IP]"
            " [--rate=PPS] [--client-cpus=N] [--timeout=MS]\n");
        return 1;
    }
    int port = atoi(argv[1]);
    int senders = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int async_mode = 0;
    int concurrent_mode = 0;
    long rate_pps = 0; // 0 = no rate cap (blast)
    int client_cpus = 1;
    long timeout_ms = 100;
    const char *host = "127.0.0.1";
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--async") == 0) async_mode = 1;
        else if (strcmp(argv[i], "--concurrent") == 0) concurrent_mode = 1;
        else if (strncmp(argv[i], "--host=", 7) == 0) host = argv[i] + 7;
        else if (strncmp(argv[i], "--rate=", 7) == 0) rate_pps = atol(argv[i] + 7);
        else if (strncmp(argv[i], "--client-cpus=", 14) == 0) client_cpus = atoi(argv[i] + 14);
        else if (strncmp(argv[i], "--timeout=", 10) == 0) timeout_ms = atol(argv[i] + 10);
    }

    if (concurrent_mode && async_mode) {
        fprintf(stderr, "--concurrent and --async are mutually exclusive\n");
        return 1;
    }
    // For sync/async modes, `senders` is the total socket count and is
    // capped at 64 (the static pid table). For concurrent mode it's
    // the per-thread slot count, allowed up to 256.
    int senders_max = concurrent_mode ? 256 : 64;
    if (senders < 1 || senders > senders_max) {
        fprintf(stderr, "senders must be 1-%d\n", senders_max);
        return 1;
    }
    if (client_cpus < 1) client_cpus = 1;
    if (!concurrent_mode && client_cpus > senders) client_cpus = senders;
    if (client_cpus > 32) client_cpus = 32;

    // Result slot count: sync/async are per-sender, concurrent is per-thread.
    int n_slots_total = concurrent_mode ? client_cpus : senders;
    size_t shm_size = sizeof(struct result) * n_slots_total;
    struct result *results = mmap(NULL, shm_size,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (results == MAP_FAILED) { perror("mmap"); return 1; }
    memset(results, 0, shm_size);

    if (concurrent_mode) {
        // Concurrent mode: T pthreads, each maintains `senders` slots.
        // Total in-flight = senders * client_cpus. No partitioning —
        // each thread runs an independent windowed loop on its own
        // sockets; results are aggregated below.
        long timeout_us = timeout_ms * 1000;
        pthread_t tids[32];
        struct concurrent_thread_args targs[32];
        int n_threads = 0;
        for (int t = 0; t < client_cpus; t++) {
            targs[n_threads] = (struct concurrent_thread_args){
                .host = host,
                .port = port,
                .duration = duration,
                .n_slots = senders,
                .timeout_us = timeout_us,
                .out = &results[t],
            };
            if (pthread_create(&tids[n_threads], NULL,
                               concurrent_thread_entry, &targs[n_threads]) != 0) {
                perror("pthread_create");
                run_concurrent(host, port, duration, senders, timeout_us, &results[t]);
            } else {
                n_threads++;
            }
        }
        for (int t = 0; t < n_threads; t++) {
            pthread_join(tids[t], NULL);
        }
    } else if (async_mode) {
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

    long total_recv = 0, total_sent = 0, total_lost = 0;
    double max_elapsed = 0;
    for (int i = 0; i < n_slots_total; i++) {
        total_recv += results[i].count;
        total_sent += results[i].sent;
        total_lost += results[i].lost;
        if (results[i].elapsed > max_elapsed)
            max_elapsed = results[i].elapsed;
    }

    double pps = max_elapsed > 0 ? total_recv / max_elapsed : 0;

    if (concurrent_mode) {
        // Sum latency histograms across all threads so percentiles
        // reflect the full population, not just one thread.
        struct result merged = {0};
        for (int i = 0; i < n_slots_total; i++) {
            for (int b = 0; b < HIST_BUCKETS; b++) {
                merged.buckets[b] += results[i].buckets[b];
            }
            merged.overflow += results[i].overflow;
            merged.count += results[i].count;
        }
        long mp50 = percentile(&merged, 50);
        long mp99 = percentile(&merged, 99);
        long mp999 = percentile(&merged, 99.9);

        double loss_pct = total_sent > 0 ?
            100.0 * (double)total_lost / (double)total_sent : 0.0;
        // Machine-readable: RESULT <recv/sec> <p50> <p99> <p999>
        // followed by a SENT line and a LOSS line so bench.py can
        // surface both numbers without re-parsing the prose.
        printf("SENT %.0f\n", total_sent / max_elapsed);
        printf("LOSS %.4f\n", loss_pct);
        printf("RESULT %.0f %ld %ld %ld\n", pps, mp50, mp99, mp999);
        fprintf(stderr,
            "UDP echo (concurrent): %d slot(s) x %d thread(s) = %d in-flight, %ds\n",
            senders, client_cpus, senders * client_cpus, duration);
        fprintf(stderr, "  Recv rate:  %.0f pkt/s\n", pps);
        fprintf(stderr, "  Loss:       %.2f%% (%ld of %ld sent)\n",
                loss_pct, total_lost, total_sent);
        fprintf(stderr, "  Latency:    p50=%ldus p99=%ldus p99.9=%ldus\n",
                mp50, mp99, mp999);
    } else {
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
    }

    munmap(results, shm_size);
    return 0;
}
