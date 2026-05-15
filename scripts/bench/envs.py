"""Environment runners — lifecycle (build / start / stop / health-check)
for each way we can stand up the unikernel or its native twin.

Split out of the old flat bench.py: everything here owns a
`subprocess.Popen` and knows how to bring it to HTTP-ready state.
Workload-side concerns (what we send into the server) live in
`workloads.py`.
"""

import os
import platform
import shutil
import subprocess
import time

from .workloads import wait_http


def _project_root():
    """Workspace root for the bazel-build-and-run envs. Plain cwd —
    locally you run `python3 scripts/bench.py ...` from the repo root,
    and on GCP `KvmEnv` takes `--elf` so the bazel-build path is unused.
    """
    return os.getcwd()


def _bench_tap_setup_script():
    """Return the path to bench-tap-setup.sh colocated with this module."""
    path = os.path.join(os.path.dirname(__file__), "bench-tap-setup.sh")
    return path if os.path.isfile(path) else None


class QemuEnv:
    name = "qemu"
    label = "QEMU x86_64 TCG"
    tls_port_offset = 1000   # host TLS port = guest HTTP port + 1000
    udp_port_offset = 1
    tcp_echo_offset = 2
    gateway_offset = 3       # host gateway port (guest:9000)

    def build(self):
        subprocess.run(
            ["bazel", "build", "//apps/webserver:webserver_qemu_x86_64"],
            capture_output=True, cwd=_project_root(), timeout=120)

    def start(self, cpus, port):
        elf = os.path.join(_project_root(),
                           "bazel-bin/apps/webserver/webserver_qemu_x86_64.elf")
        # `-cpu max` instead of `-cpu qemu64`: the compiled crypto
        # code (p256 / chacha20poly1305 / etc.) is annotated with
        # `+avx,+avx2` in MODULE.bazel and crashes with #UD the
        # first time it emits an AVX instruction on a pre-AVX CPU
        # model. `qemu64` is pre-AVX; `max` enables every feature
        # TCG can simulate.
        cmd = ["qemu-system-x86_64", "-machine", "q35", "-cpu", "max",
               "-m", "128", "-smp", str(cpus), "-nographic",
               "-serial", f"file:/tmp/bench_{port}.log", "-no-reboot"]
        if cpus > 1:
            cmd += ["-accel", "tcg,thread=multi"]
        dev = "virtio-net-pci"
        if cpus > 1:
            dev += f",mq=on,vectors={2*cpus+2}"
        tls_port = port + self.tls_port_offset
        tcp_echo_port = port + self.tcp_echo_offset
        gateway_port = port + self.gateway_offset
        cmd += ["-device", f"{dev},netdev=net0",
                "-netdev",
                (f"user,id=net0,hostfwd=tcp::{port}-:80,"
                 f"hostfwd=tcp::{tls_port}-:443,"
                 f"hostfwd=tcp::{tcp_echo_port}-:9,"
                 f"hostfwd=tcp::{gateway_port}-:9000,"
                 f"hostfwd=udp::{port+1}-:7"),
                "-kernel", elf]
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()

    def core_label(self, cpus):
        return f"QEMU {cpus}c" + (" MTTCG" if cpus > 1 else "")


class KvmEnv:
    name = "kvm"
    label = "QEMU x86_64 KVM"

    # Guest IP served by dnsmasq on the GCP host tap0; see
    # scripts/bench/bench-tap-setup.sh. Fixed MAC pins this address.
    TAP_IF = "tap0"
    GUEST_MAC = "52:54:00:12:34:56"
    GUEST_IP = "10.20.30.10"
    GUEST_PORT = 80
    GUEST_TLS_PORT = 443
    GUEST_UDP_PORT = 7
    GUEST_H3_PORT = 443     # H3/QUIC over UDP (same port number as
                            # TLS-over-TCP; the unikernel binds both).
    GUEST_TCP_ECHO_PORT = 9
    GUEST_GATEWAY_PORT = 9000

    # Path to pre-staged ELF; set via --elf. If None, bazel build runs.
    elf_override = None

    def build(self):
        if not self.elf_override:
            subprocess.run(
                ["bazel", "build", "//apps/webserver:webserver_qemu_x86_64"],
                capture_output=True, cwd=_project_root(), timeout=120)
        # Ensure tap0 + dnsmasq + NAT are up before the first qemu
        # launch. Idempotent (the script itself is), so re-running
        # on every bench invocation is cheap and replaces the old
        # requirement that the user manually install the script at
        # /usr/local/sbin and run it as a separate ssh step.
        script = _bench_tap_setup_script()
        if script:
            subprocess.run(["sudo", script], capture_output=True, timeout=10)

    def start(self, cpus, port):
        elf = self.elf_override or os.path.join(
            _project_root(),
            "bazel-bin/apps/webserver/webserver_qemu_x86_64.elf")
        # tap backend with vhost-net + multi-queue. Multi-queue is only
        # requested when cpus > 1 because QEMU rejects queues=1 on tap.
        cmd = ["qemu-system-x86_64", "-machine", "q35", "-accel", "kvm", "-cpu", "host",
               "-m", "128", "-smp", str(cpus), "-nographic",
               "-serial", f"file:/tmp/bench_{port}.log", "-no-reboot"]
        # The host tap0 is created with IFF_MULTI_QUEUE; QEMU rejects
        # opening it with queues=1 ("could not configure /dev/net/tun:
        # Invalid argument"), so use max(cpus, 2) on the netdev side.
        nqueues = max(cpus, 2)
        netdev = (f"tap,id=net0,ifname={self.TAP_IF},script=no,downscript=no,"
                  f"vhost=on,queues={nqueues}")
        # Always pass `mq=on` and `vectors` on the device, even at 1c.
        # Without it, vhost-net silently drops UDP under high send rates
        # when the netdev has more queues than the device exposes (the
        # guest still negotiates only `cpus` queue pairs because the
        # driver gates activation on cpu count, but the device side
        # needs mq=on to wire up vhost properly with the multi-queue tap).
        #
        dev = f"virtio-net-pci,mac={self.GUEST_MAC},mq=on,vectors={2*nqueues+2}"
        cmd += ["-device", f"{dev},netdev=net0",
                "-netdev", netdev,
                "-kernel", elf]
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()
        # vhost-net's per-queue worker threads occasionally hang on to a
        # multi-queue tap fd just long enough that the next QEMU instance
        # finds the device in a half-broken state — udp_async at 1c then
        # records 0 pkt/s for several runs in a row even though the same
        # command works in isolation. Tearing tap0 down and re-creating
        # it between iterations gives vhost a clean slate and eliminates
        # the flake. Cheap (~30ms) compared to a 6s test.
        script = _bench_tap_setup_script()
        try:
            subprocess.run(
                ["sudo", "ip", "link", "del", self.TAP_IF],
                capture_output=True, timeout=5)
            if script:
                subprocess.run(
                    ["sudo", script], capture_output=True, timeout=5)
        except Exception:
            pass

    def core_label(self, cpus):
        return f"KVM {cpus}c"


class QemuAarch64Env:
    name = "qemu-arm"
    label = "QEMU aarch64 TCG"
    tls_port_offset = 1000   # host TLS port = guest HTTP port + 1000
    udp_port_offset = 1
    tcp_echo_offset = 2
    gateway_offset = 3

    def build(self):
        subprocess.run(
            ["bazel", "build", "//apps/webserver:webserver_qemu_aarch64"],
            capture_output=True, cwd=_project_root(), timeout=120)

    def start(self, cpus, port):
        img = os.path.join(_project_root(),
                           "bazel-bin/apps/webserver/webserver_qemu_aarch64.img")
        tls_port = port + self.tls_port_offset
        tcp_echo_port = port + self.tcp_echo_offset
        gateway_port = port + self.gateway_offset
        cmd = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "max",
               "-m", "128", "-smp", str(cpus), "-nographic",
               "-serial", f"file:/tmp/bench_{port}.log", "-no-reboot",
               "-device", "virtio-net-device,netdev=net0",
               "-netdev",
               (f"user,id=net0,hostfwd=tcp::{port}-:80,"
                f"hostfwd=tcp::{tls_port}-:443,"
                f"hostfwd=tcp::{tcp_echo_port}-:9,"
                f"hostfwd=tcp::{gateway_port}-:9000,"
                f"hostfwd=udp::{port+1}-:7"),
               "-kernel", img]
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()

    def core_label(self, cpus):
        return f"ARM {cpus}c"


class DockerEnv:
    name = "docker"
    label = "Docker/Linux"
    cid = None

    def build(self):
        root = _project_root()
        # `:webserver_bin` is the underlying rust_binary;
        # `:webserver_native` is the BUILD-defaults launcher script.
        # Docker only needs the binary — env vars are set via
        # `docker run -e`, so the launcher's defaults are redundant.
        subprocess.run(
            ["bazel", "build", "--config=x86_64-linux", "//apps/webserver:webserver_bin"],
            capture_output=True, cwd=root, timeout=120)
        bench_dir = os.path.join(root, "bench")
        src = os.path.join(root, "bazel-bin/apps/webserver/webserver_bin")
        if os.path.exists(src):
            os.makedirs(bench_dir, exist_ok=True)
            shutil.copy2(src, os.path.join(bench_dir, "webserver_native"))
            subprocess.run(["docker", "build", "-q", "-t", "webserver_linux", bench_dir],
                           capture_output=True, timeout=60)

    def start(self, cpus, port):
        r = subprocess.run(
            ["docker", "run", "--rm", "-d", "-p", f"{port}:80", "webserver_linux"],
            capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            self.cid = r.stdout.strip()
        return self  # return self as "proc" handle

    def stop(self, proc):
        if self.cid:
            subprocess.run(["docker", "stop", self.cid], capture_output=True, timeout=10)
            self.cid = None

    def poll(self):
        return None if self.cid else 1

    def core_label(self, cpus):
        return "Docker"


class NativeEnv:
    name = "native"
    label = "Native (POSIX)"
    # Offset added to the HTTP port to pick a non-overlapping TLS
    # port. Mirrors the VM envs' `tls_port_offset`. Picked to sit
    # well above the ephemeral port range so it doesn't collide with
    # outbound sockets, and to be predictable for the bench
    # dispatch loop.
    tls_port_offset = 1000
    udp_port_offset = 1      # host UDP port = guest HTTP port + 1
    tcp_echo_offset = 2      # async TCP echo port (guest:9)
    gateway_offset = 3       # async gateway port (guest:9000)
    h3_port_offset = 1500    # host UDP port for the H3/QUIC listener
                             # (guest UDP:443). Picked above
                             # `tls_port_offset` so the human-readable
                             # mapping (`bench_port + 1500` ↔ H3) is
                             # easy to spot when reading log output.

    # Path to pre-staged native binary; set via --native-bin. If None, bazel build runs.
    bin_override = None

    def build(self):
        if self.bin_override:
            return  # Pre-staged binary; nothing to build.
        config = "aarch64-macos" if platform.machine() in ("arm64", "aarch64") else "x86_64-linux"
        # Bypass the `:webserver_native` launcher (which sets BUILD
        # port-fwd defaults) and build the underlying rust_binary
        # directly — `start()` sets every `UNIKERNEL_*` it needs, so
        # the launcher's defaults would be no-ops anyway.
        subprocess.run(
            ["bazel", "build", f"--config={config}", "//apps/webserver:webserver_bin"],
            capture_output=True, cwd=_project_root(), timeout=120)

    def start(self, cpus, port):
        bin_path = self.bin_override or os.path.join(
            _project_root(), "bazel-bin/apps/webserver/webserver_bin")
        if not os.path.exists(bin_path):
            return None
        env = os.environ.copy()
        env["UNIKERNEL_TCP_80"] = str(port)
        env["UNIKERNEL_TCP_443"] = str(port + self.tls_port_offset)
        env["UNIKERNEL_UDP_7"] = str(port + 1)
        # H3/QUIC listener (guest UDP:443).
        env["UNIKERNEL_UDP_443"] = str(port + NativeEnv.h3_port_offset)
        # Async TCP echo benches target guest port 9 via the
        # `tcp_echo_offset` offset below.
        env["UNIKERNEL_TCP_9"] = str(port + NativeEnv.tcp_echo_offset)
        env["UNIKERNEL_TCP_9000"] = str(port + NativeEnv.gateway_offset)
        env["UNIKERNEL_CPUS"] = str(cpus)
        return subprocess.Popen(
            [bin_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()

    def core_label(self, cpus):
        return f"Native {cpus}t"


class HvfEnv:
    name = "hvf"
    label = "HVF"
    udp_port_offset = 10000  # host UDP port = guest port + 10000
    tls_port_offset = 1000   # host TLS port = guest HTTP port + 1000
    tcp_echo_offset = 2000   # host TCP echo port (guest:9)
    gateway_offset = 3000    # host gateway port (guest:9000)
    h3_port_offset = 11000   # host UDP port for the H3/QUIC listener
                             # (guest UDP:443). Disjoint from
                             # `udp_port_offset` (which forwards the
                             # echo listener at guest UDP:7).

    def build(self):
        # `:webserver_hvf` bundles both the transitioned aarch64
        # unikernel .img and the host-built HVF runner under one
        # target — the variant rule's transition scopes the
        # platform override to just the guest-side sub-graph, so a
        # single `bazel build` covers both.
        subprocess.run(
            ["bazel", "build", "//apps/webserver:webserver_hvf"],
            capture_output=True, cwd=_project_root(), timeout=240)

    def start(self, cpus, port):
        root = _project_root()
        # `:webserver_hvf`'s runfiles bundle the guest .img (co-
        # located symlink) and the host hvf-runner binary (natural
        # runfile path, not symlinked).
        img = os.path.join(root, "bazel-bin/apps/webserver/webserver_hvf.img")
        run_hvf = os.path.join(root, "bazel-bin/tools/hvf-runner/run-hvf")
        log = open(f"/tmp/hvf_{port}.log", "w")
        udp_port = port + self.udp_port_offset
        tls_port = port + self.tls_port_offset
        tcp_echo_port = port + self.tcp_echo_offset
        gateway_port = port + self.gateway_offset
        h3_port = port + self.h3_port_offset
        # -p tcp:HOST:GUEST forwards HTTP to guest:80; -p tcp:HOST:443
        # forwards HTTPS to guest:443; -p tcp:HOST:9 forwards the
        # async TCP echo test; -p tcp:HOST:9000 forwards the
        # gateway listener; -p udp:HOST:7 forwards UDP echo;
        # -p udp:HOST:443 forwards the H3/QUIC listener.
        # 512 MB so the fanout_tcp workload's thousand-conn shape
        # — each ephemeral UDP binding allocates an inbox on the
        # kernel heap — fits with comfortable headroom. Smaller
        # workloads cost the host nothing extra; the heap grows
        # dynamically and unused pages stay unfaulted.
        return subprocess.Popen(
            [run_hvf, img,
             "--ram=512", f"--cpus={cpus}",
             "-p", f"tcp:{port}:80",
             "-p", f"tcp:{tls_port}:443",
             "-p", f"tcp:{tcp_echo_port}:9",
             "-p", f"tcp:{gateway_port}:9000",
             "-p", f"udp:{udp_port}:7",
             "-p", f"udp:{h3_port}:443"],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def wait_proxy_ready(self, port, proc, timeout=30):
        """Wait for the HTTP server to be reachable on the proxy port."""
        return wait_http(port, timeout)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        time.sleep(0.5)

    def core_label(self, cpus):
        return f"HVF {cpus}c"


class RemoteEnv:
    """Bench target that's already running somewhere else. No build, no
    start, no stop — just a reachable `ip:port` the workload hits.
    Intended for benching a dedicated unikernel VM (e.g. the
    `unikernel-webserver` GCE instance) rather than a VM we spawn
    locally. Set `--target 10.0.0.1` on the CLI; leave `--cores` as
    whatever the remote VM actually has so the `*_per_core` workloads
    scale pressure correctly.
    """

    name = "remote"
    label = "Remote"
    # Signals to the bench-harness loop that the "==> Building …"
    # print + `build()` call is a no-op for this env (the binary
    # is already running on a different VM). Other envs leave this
    # at the default of `True`.
    needs_build = False

    # Matches KvmEnv so `isinstance` branches that dispatch on
    # "has GUEST_IP/PORT" pick up the same values. Override GUEST_IP
    # via CLI `--target`.
    GUEST_IP = None
    GUEST_PORT = 80
    GUEST_TLS_PORT = 443
    GUEST_UDP_PORT = 7
    GUEST_H3_PORT = 443
    GUEST_TCP_ECHO_PORT = 9
    GUEST_GATEWAY_PORT = 9000

    def __init__(self):
        # Non-None sentinel so `_current["proc"]` cleanup logic treats
        # a started RemoteEnv as "running". It's never actually exec'd.
        self._sentinel = object()

    def build(self):
        pass

    def start(self, cpus, port):
        # `cpus` and `port` are ignored — the remote VM is what it is.
        return self._sentinel

    def stop(self, proc):
        pass

    def core_label(self, cpus):
        return f"Remote {cpus}c"


ENV_MAP = {
    "qemu": QemuEnv,
    "kvm": KvmEnv,
    "qemu-arm": QemuAarch64Env,
    "hvf": HvfEnv,
    "docker": DockerEnv,
    "native": NativeEnv,
    "remote": RemoteEnv,
}


def start_env_verified(env, cpus, port):
    """Start env and verify HTTP readiness.

    For HVF: wait for the proxy TCP port to be connectable, then poll
    HTTP for the VM to finish booting. Retry once if first attempt fails.
    For other envs: poll HTTP directly, no retry.
    """
    proc = env.start(cpus, port)
    if proc is None:
        return None

    if isinstance(env, HvfEnv):
        # Phase 1: wait for proxy TCP port to be connectable (fast, <1s normally).
        if not env.wait_proxy_ready(port, proc, timeout=30):
            env.stop(proc)
            # Retry once — network interface may not have been released yet.
            proc = env.start(cpus, port)
            if proc is None:
                return None
            if not env.wait_proxy_ready(port, proc, timeout=30):
                env.stop(proc)
                return None
        # Phase 2: poll HTTP until the VM finishes booting.
        if wait_http(port):
            return proc
        env.stop(proc)
        return None
    elif isinstance(env, (KvmEnv, RemoteEnv)):
        if wait_http(env.GUEST_PORT, host=env.GUEST_IP):
            return proc
        env.stop(proc)
        return None
    else:
        if wait_http(port):
            return proc
        env.stop(proc)
        return None
