# Benchmarking & GCE scripts

How to benchmark the unikernel webserver — locally and on GCE — and a
reference for every benchmark and `gcloud` script in `scripts/`.

The system has five layers:

| Layer | Script(s) | What it does |
|---|---|---|
| Harness | `bench.py` + `bench/` | The benchmark engine — environments, workloads, the results table. |
| Local bench | `bench.py --env hvf,qemu,native,docker` | Boots the unikernel on this machine and loads it. |
| Nested-KVM GCE bench | `gcp-bench.sh` | Runs the harness on a GCE host; unikernel + loadgen co-located under nested KVM. |
| Production-shape GCE bench | `gcp-deploy-bench.sh` | Unikernel as a *real* GCE VM (gVNIC); loadgen on a separate VM. |
| GCE VM control / deploy | `gcp.sh`, `deploy-gcloud.sh` | Start/stop/ssh dev VMs; build + upload a GCE custom image. |

## Quick reference

| I want to… | Command |
|---|---|
| Bench locally on macOS (fastest path) | `python3 scripts/bench.py --env hvf --cores 1,4` |
| Bench locally, portable (slow, TCG) | `python3 scripts/bench.py --env qemu` |
| Bench one workload | `python3 scripts/bench.py --env hvf --workload get_tcp` |
| Bench on GCE under nested KVM | `./scripts/gcp-bench.sh --env kvm --cores 1,4,8` |
| Bench the unikernel as a real GCE VM | `./scripts/gcp-deploy-bench.sh --cores 1,4,8` |
| Start / stop / ssh the GCE dev VM | `./scripts/gcp.sh {start,stop,ssh}` |
| Deploy the unikernel as a GCE image | `./scripts/deploy-gcloud.sh deploy` |

> The GCE VMs live in zone **`us-west1-c`**. Every script defaults
> there (`gcp.sh` via `GCP_ZONE`, `gcp-deploy-bench.sh` /
> `deploy-gcloud.sh` via `WAITLESS_GCE_ZONE`); set those env vars
> only to target a different zone.

---

## The harness — `bench.py`

`scripts/bench.py` is a 21-line shim: it puts `scripts/` on `sys.path`
and calls `bench.cli.main()`. The real engine is `scripts/bench/`:

- `bench/cli.py` — argparse, the `WORKLOADS` registry, the run loop.
- `bench/envs.py` — one lifecycle class per environment (build / start
  / health-check / stop).
- `bench/workloads.py` — the load drivers (`wrk`, the Rust `loadgen`,
  the C `udp_bench`) and stat collection.

> The `if __name__ == "__main__"` guard in `bench.py` is load-bearing:
> macOS Python uses `spawn` for multiprocessing, which re-imports the
> entry module in every worker — without the guard each worker re-runs
> `main()`.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--env` | `qemu` | Comma-separated environments (see below). `all` = `qemu,qemu-arm,hvf,docker,native`; `vm` = `qemu,qemu-arm,hvf`. |
| `--cores` | auto | Comma-separated core counts. Auto = `1,<host/2>` local, `1,<host>` when `remote` is included. |
| `--workload` | tier-`default` set | Comma-separated workload names; preserves order. Unknown name → error + list. |
| `--duration` | `5` | Seconds per workload. |
| `--elf` | — | Pre-built KVM ELF; skips the bazel build (`kvm` env only). |
| `--native-bin` | — | Pre-built native binary; skips the build (`native` env only). |
| `--target` | — | Target IP. **Required** for `--env remote`. |

The run loop, per environment: build → for each (core count, workload)
start the guest, wait for HTTP readiness, drive the load, measure
client CPU, stop the guest. Three consecutive readiness failures
(`SKIP (not ready)`) abort that core count. The summary table has
workloads as rows, `(env, cores)` as columns, plus scaling multipliers.
A `⚠` on a cell means the *loadgen* used ≥70% of the host — the result
is probably client-bound, not server-bound.

### Environments

| `--env` | Runs on | Platform | Notes |
|---|---|---|---|
| `qemu` | QEMU x86_64 **TCG** (software emulation) | any | Portable, slowest. `-cpu max` for AVX; MTTCG (a host thread per vCPU) when cores > 1. Single virtio RX queue ⇒ **Tier 2**. |
| `qemu-arm` | QEMU aarch64 TCG | any | ARM build; single-core only (no MTTCG on ARM TCG). |
| `hvf` | Apple Hypervisor.framework | **macOS only** | The native arm64 dev path; multi-queue ⇒ **Tier 1**. Logs: `/tmp/hvf_<port>.{log,serial.log}`. |
| `kvm` | QEMU x86_64 + **KVM** | Linux w/ KVM | Hardware-accelerated; tap0 + vhost-net. Fixed guest IP `10.20.30.10`. tap setup needs `sudo`. |
| `docker` | native binary in a container | any | Single-core. The Linux/Docker baseline. |
| `native` | POSIX binary, no VM | any | No hypervisor overhead — the upper bound. |
| `remote` | an already-running VM | any | No build/start/stop; needs `--target <ip>`. Used by `gcp-deploy-bench.sh`. |

### Workloads

Workloads live in the `WORKLOADS` registry (`bench/cli.py`); each entry
is typed (`tcp`, `https`, `tls_handshake`, `echo_udp`, `http_upload`,
`h3_health`, `gateway`, …) and carries per-core scaling hints
(`conns_per_core`, `threads_per_core`, `parallelism_per_core`). Each
has a `tier`:

- **`default`** — run whenever `--workload` is omitted.
- **`available`** — implemented but off by default; name it explicitly
  to run it (e.g. `get_tls`, `get_tls_single`, `get_tls_fresh_resume`,
  `upload_1m_tcp`, `fanout_tcp`).
- **`todo`** — a registered stub; prints a `TODO` row, never runs.

The default set: `get_tcp_single`, `get_tcp`, `get_tcp_fresh`,
`echo_udp`, `download_64k_tcp`, `download_64k_tls`, `get_tls_fresh`,
`download_64k_quic`, `upload_32k_tcp`, `upload_32k_tls`.

Load drivers: HTTP keep-alive throughput via `wrk`; fresh-connection,
TLS-handshake, HTTP/3 and upload workloads via the Rust `loadgen`
(`bench/loadgen/`, built on first use via `cargo build --release`);
UDP via the C `udp_bench`. `echo_udp` sweeps a concurrency ladder
(8…512 slots) and reports the best.

### Local examples

```sh
# macOS: HVF at 1 and 4 cores, default workloads
python3 scripts/bench.py --env hvf --cores 1,4

# Tier-2 path (single virtio queue) at 3 cores — QEMU MTTCG
python3 scripts/bench.py --env qemu --cores 1,3 --duration 10

# One workload, against the native (no-VM) upper bound
python3 scripts/bench.py --env native --workload get_tcp
```

### Before / after — measuring a change

`bench.py` prints one table per run; there is no built-in baseline or
compare mode. To measure a change, bench two commits and diff by eye.
A `git worktree` keeps the baseline checkout (and its `bazel` cache)
separate from the change:

```sh
git worktree add /tmp/uni-base <baseline-commit>
(cd /tmp/uni-base && python3 scripts/bench.py --env hvf,qemu --cores 1,3 --duration 10)
python3 scripts/bench.py --env hvf,qemu --cores 1,3 --duration 10   # the change
```

- **3 runs per side, take the median.** QEMU TCG has no fixed
  instruction timing and MTTCG adds scheduler jitter; single QEMU
  runs swing widely (a `get_tcp_single` 3c cell has varied 3–4×
  run-to-run). HVF is hardware-accelerated and much steadier.
- **Trust the control workloads.** `get_tcp` and `get_tls_fresh` are
  the steadiest — a >3% move in their *median* is a real signal; a
  single-run outlier is not.
- Run the two sides **sequentially**. A concurrent build or VM steals
  host cores and skews results client-bound.
- For an RX-path change the QEMU side is mandatory, not optional —
  see the Tier-1 / Tier-2 gotcha below.

---

## GCE benchmarking

Two GCE VMs, both `c3-highcpu-8`, SPOT, zone `us-west1-c`:

- **`kvm-vm`** — the loadgen host. Also runs the unikernel under
  *nested* QEMU/KVM for `gcp-bench.sh`.
- **`waitless-webserver`** — the unikernel running as a *real* GCE VM
  (gVNIC). The target for `gcp-deploy-bench.sh`.

Both scripts start the VM(s) they need and **stop them on exit** unless
`--keep-running` is passed, so idle compute isn't billed.

### `gcp-bench.sh` — nested-KVM bench

Runs the harness *on* `kvm-vm`: the unikernel (under nested KVM) and the
loadgen co-locate on the one host, talking over loopback. GCE's virtio
can't spread RX across queues, so this exercises the **Tier 2**
single-queue path.

```sh
./scripts/gcp-bench.sh --env kvm --cores 1,4,8 \
    --workload get_tcp,echo_udp --duration 10
```

| Flag | Default | Meaning |
|---|---|---|
| `--env` | `kvm,native` | Forwarded to `bench.py`; decides which binaries to build/sync. |
| `--cores` / `--duration` / `--workload` | `1,2,3` / `10` / all | Forwarded to `bench.py`. |
| `--no-build` | — | Skip the local bazel build; reuse what's on the VM. |
| `--keep-running` | — | Don't stop `kvm-vm` afterwards. |

It builds the x86_64 binaries locally, auto-starts `kvm-vm`, `rsync`s
the harness + binaries, and runs `bench.py` over SSH. Env vars:
`GCP_SSH_HOST` (default `gcp`), `GCP_REMOTE_DIR` (default `bench`).

### `gcp-deploy-bench.sh` — production-shape bench

Deploys the unikernel as the real `waitless-webserver` GCE VM and
drives `loadgen` against it from `kvm-vm` over the GCE network — the
gVNIC datapath, **Tier 1**.

```sh
./scripts/gcp-deploy-bench.sh --cores 1,4,8 --duration 10
./scripts/gcp-deploy-bench.sh --no-redeploy --keep-running   # iterate
```

| Flag | Default | Meaning |
|---|---|---|
| `--cores` / `--duration` / `--workload` | `1,2,4` / `5` / all-default | `bench.py --env remote` parameters. |
| `--no-redeploy` | — | Skip the image rebuild + upload; reuse what's deployed. |
| `--keep-running` | — | Leave both VMs up afterwards. |
| `--par N` | — | "Raw" mode: one direct `loadgen` call at parallelism `N`, bypassing the harness. |
| `--warmup` / `--endpoint` | `1` / `/health` | Raw-mode only. |

It calls `deploy-gcloud.sh deploy` (unless `--no-redeploy`), syncs the
harness to `kvm-vm`, builds `loadgen` there, tunes the loadgen VM's
sysctls (`tcp_tw_reuse`, widened `ip_local_port_range` — fresh-conn
workloads exhaust ephemeral ports otherwise), then runs `bench.py --env
remote --target <waitless-webserver IP>`. Env vars: `WAITLESS_GCE_*`
(see below) plus `GCP_KVM_VM_NAME` / `GCP_KVM_VM_ZONE`.

---

## GCE VM control — `gcp.sh`

Manages a single dev instance (`kvm-vm` by default). `gcp-bench.sh`
calls it under the hood.

```sh
./scripts/gcp.sh <command>
```

| Command | Action |
|---|---|
| `status` / `ip` | Instance status + external IP. |
| `start` / `stop` | Start (refreshes the `~/.ssh/config` HostName — GCE re-rolls the IP each start) / stop. |
| `ssh` | Interactive SSH session. |
| `run` | Build + push the ELF, launch nested QEMU+KVM with tap/vhost, forward the serial console interactively (Ctrl-] detaches). |
| `serve` | Like `run` but detached, public `:80`/`:443`, logs to `/tmp/webserver.log`. |
| `test` | Build + push, run sandboxed HTTP + UDP smoke tests; exit non-zero on failure. |
| `kill` | Kill the nested QEMU on the VM (leaves the GCE instance running). |

Env vars: `GCP_PROJECT` (`unikernel-dev`), `GCP_ZONE`
(`us-west1-c`), `GCP_INSTANCE` (`kvm-vm`),
`GCP_SSH_HOST` (`gcp`), `WAITLESS_MEMORY` (`128` MB),
`WAITLESS_CPUS` (remote `nproc`).

## Image deployment — `deploy-gcloud.sh`

Builds the unikernel into a GCE custom image: Limine ISO → `disk.raw`
padded to 10 GiB → GNU sparse tarball → GCS upload → image import → VM
launch with serial logging.

```sh
./scripts/deploy-gcloud.sh deploy        # full build + upload + launch
./scripts/deploy-gcloud.sh logs          # follow the VM serial port
./scripts/deploy-gcloud.sh {status,stop,start,ip,delete,purge}
./scripts/deploy-gcloud.sh build-only    # build disk.raw, don't upload
./scripts/deploy-gcloud.sh qemu-test     # smoke-boot disk.raw locally
```

Env vars: `WAITLESS_GCE_PROJECT`, `WAITLESS_GCE_ZONE` (`us-west1-c`),
`WAITLESS_GCE_MACHINE` (`c3-highcpu-8`), `WAITLESS_GCE_NAME`
(`waitless-webserver`), `WAITLESS_GCS_BUCKET`, `QUEUE_COUNT` (`8` —
match vCPUs), `WAITLESS_GCE_PREEMPTIBLE` (`1` = SPOT),
`LEGACY_VIRTIO_NIC` (`1` = legacy virtio instead of gVNIC, for A/B
comparison).

> gVNIC (default) hashes RX 4-tuples across queue pairs → **Tier 1**.
> Legacy virtio on GCE negotiates multi-queue but Andromeda doesn't
> hash RX, so all flows land on qp0 → **Tier 2**.

`scripts/deploy-aws.sh` is the AWS analog — out of scope for this doc.

## How the scripts compose

```
gcp-bench.sh ───────► kvm-vm
   └─ gcp.sh start          (auto-start)         nested QEMU+KVM + loadgen,
   └─ rsync harness                              both on loopback  → Tier 2

gcp-deploy-bench.sh ──► waitless-webserver  +  kvm-vm
   └─ deploy-gcloud.sh deploy   (the target)      (the loadgen client)
   └─ bench.py --env remote --target <uni ip>    over the GCE network → Tier 1

gcp.sh {run,serve,test} ► kvm-vm   (interactive dev: build → push → nested QEMU)
deploy-gcloud.sh ───────► waitless-webserver   (build a GCE custom image)
```

## Gotchas

- **A wrong `GCP_ZONE` fails quietly.** `GCP_ZONE` defaults to
  `us-west1-c`, where the VMs live — but if it is overridden to a
  zone with no instance, `gcp.sh status` finds nothing, so
  `gcp-bench.sh` silently *skips* the VM-start, then SSHes a stale
  IP and times out. If a bench mysteriously can't reach the VM,
  check `gcloud compute instances list` for the real zone.
- **VM teardown / billing.** `gcp-bench.sh` and `gcp-deploy-bench.sh`
  stop their VMs on exit by default. `--keep-running` skips that —
  remember to stop them yourself (`gcp.sh stop`, or `gcloud compute
  instances stop`). Check with `gcloud compute instances list`.
- **Co-locate the GCE VMs.** Both must share a zone; cross-zone RTT
  (~5 ms) RTT-bounds fresh-connection workloads.
- **SPOT preemption.** The VMs are preemptible — fine for iteration,
  but a run can be interrupted. Set `WAITLESS_GCE_PREEMPTIBLE=0` for
  an on-demand VM when a clean multi-point sweep matters.
- **`SKIP (not ready)` on `gcp-bench.sh --env kvm` — nested
  virtualization on `kvm-vm`.** *Diagnosed + fixed 2026-05-18.* `kvm-vm`
  had GCE's per-instance nested-virt opt-in unset
  (`advancedMachineFeatures.enableNestedVirtualization` absent), so its
  guest CPU exposed no `vmx` flag, `/dev/kvm` did not exist, and
  `kvm_intel` / `vhost_net` never loaded. Every `-accel kvm` QEMU launch
  — `bench.py`'s `KvmEnv`, and equally `gcp.sh run`/`serve`/`test` —
  died at accelerator init with `Could not access KVM kernel module: No
  such file or directory`, exiting (code 1) *before* it opened the
  `-serial file:` chardev. No `/tmp/bench_<port>.log` was ever written,
  so there was no guest serial console to inspect — and `KvmEnv.start()`
  runs QEMU with `stderr=DEVNULL`, which discarded the message too. The
  harness then polled `http://10.20.30.10/health` for 20 s, got nothing,
  and after 3 strikes printed `SKIP (not ready)`. (The two paths that
  *do* work use no nested KVM: local `--env qemu` is TCG, and the real
  `waitless-webserver` GCE VM is itself the non-nested guest.)

  Nested virtualization is now **enabled** on `kvm-vm` and `--env kvm`
  produces real, core-scaling numbers again (`c3-highcpu-8` supports
  it). To re-apply it if `kvm-vm` is recreated: the opt-in must be set
  while the VM is stopped, and `gcloud compute instances update` has
  *no* nested-virt flag (SDK 566) — so either set it at create time
  (`gcloud compute instances create … --enable-nested-virtualization`),
  or patch the stopped instance through the Compute API:

  ```sh
  gcloud compute instances stop kvm-vm --zone=us-west1-c
  U=https://compute.googleapis.com/compute/v1/projects/unikernel-dev/zones/us-west1-c/instances/kvm-vm
  T=$(gcloud auth print-access-token)
  curl -s -H "Authorization: Bearer $T" "$U" > /tmp/kvm-vm.json
  python3 - <<'PY'
  import json
  d = json.load(open("/tmp/kvm-vm.json"))
  d.setdefault("advancedMachineFeatures", {})["enableNestedVirtualization"] = True
  json.dump(d, open("/tmp/kvm-vm.json", "w"))
  PY
  curl -s -X PUT -H "Authorization: Bearer $T" \
       -H "Content-Type: application/json" --data @/tmp/kvm-vm.json "$U"
  gcloud compute instances start kvm-vm --zone=us-west1-c
  ```

  Confirm with `ls /dev/kvm` and `grep -c vmx /proc/cpuinfo` on the VM.
  Note `--env kvm` is a *redundant* measurement regardless: the Tier-2
  single-queue RX path it exercises is also covered by local `--env
  qemu` at multiple cores (MTTCG gives genuine multi-threaded
  concurrency).

  *(Resolved 2026-05-18.)* TCP **upload** workloads (`upload_*`) first
  stalled here (~1.3 s/req, throughput near zero) while `get_*` /
  `echo_udp` were fine: the virtio-net driver negotiated guest RX
  offloads (`GUEST_TSO4` / `MRG_RXBUF`) that its single-descriptor RX
  path can't honour, so vhost-net's GRO-coalesced multi-buffer
  super-frames were shredded. Fixed by masking those bits — see
  `VIRTIO_NET_RX_OFFLOAD_MASK` in `drivers/src/virtio.rs`.
- **`--cpu max` / AVX.** The p256 + chacha20poly1305 crates emit AVX;
  QEMU's default `qemu64` lacks it and faults at TLS init. Every
  bench-driven QEMU invocation passes `-cpu max` (or `-cpu host` under
  KVM/HVF) — a new QEMU invocation outside the harness must too.
- **Tier 1 vs Tier 2 — an RX-path change must bench both.** Which RX
  dispatch tier a run exercises depends on whether the NIC spreads RX
  across queues — see [networking.md](networking.md). HVF and
  real-GCE-gVNIC are Tier 1; local QEMU and GCE-under-KVM (and
  legacy-virtio GCE) are Tier 2. The two paths are *different code*:
  Tier 1 polls a per-core queue and runs the stack inline; Tier 2
  routes frames cross-core through `net::distribute_frame` and the
  per-core `kernel::RxInbox`. A change to that cross-core path benched
  only on HVF — or covered only by `test_hvf` — has **zero Tier-2
  coverage**: HVF never executes `distribute_frame` or `RxInbox` at
  all. Always add `--env qemu --cores 1,3` (single virtio queue ⇒
  Tier 2; MTTCG ⇒ genuine multi-core) for any RX-path change. This is
  not hypothetical: a cross-core `RxInbox` rewrite once passed
  `test_hvf` clean while collapsing QEMU-3c throughput ~90% — only the
  Tier-2 bench caught it.
