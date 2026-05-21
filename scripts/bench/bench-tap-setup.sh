#!/usr/bin/env bash
# bench-tap-setup.sh — Idempotent host-side networking for KVM benchmarks.
#
# Creates a multi-queue tap device named tap0 owned by the bench user,
# assigns 10.20.30.1/24, and ensures dnsmasq is serving DHCP on it. The
# unikernel boots with a fixed MAC (52:54:00:12:34:56) which dnsmasq
# pins to 10.20.30.10, so the bench harness can connect to the guest
# at a known address.
#
# This script is bundled as a runfile of //scripts/bench and invoked
# by `KvmEnv.build()` / `KvmEnv.stop()` through the bazel runfiles
# lookup, so bench.zip ships its own copy — no /usr/local/sbin
# install required on the bench host. The script stays idempotent,
# so calling it before every KVM test is cheap and resets any stale
# tap state left by a prior run.
#
# Requires: ip (iproute2), dnsmasq, and a /etc/dnsmasq.d/waitless-bench.conf
# with at minimum:
#     interface=tap0
#     bind-interfaces
#     except-interface=lo
#     dhcp-range=10.20.30.10,10.20.30.20,12h
#     dhcp-host=52:54:00:12:34:56,10.20.30.10
# This script writes that file if it's missing.

set -e

USER_NAME="${1:-${SUDO_USER:-$(id -un)}}"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (use sudo)" >&2
    exit 1
fi

# Create dnsmasq config if missing.
DNSMASQ_CONF=/etc/dnsmasq.d/waitless-bench.conf
if [ ! -f "$DNSMASQ_CONF" ]; then
    cat >"$DNSMASQ_CONF" <<'EOF'
# Unikernel benchmark: minimal DHCP for tap0
interface=tap0
bind-interfaces
except-interface=lo
no-resolv
no-hosts
domain-needed
bogus-priv
dhcp-authoritative
dhcp-range=10.20.30.10,10.20.30.20,12h
dhcp-host=52:54:00:12:34:56,10.20.30.10
EOF
fi

# Create tap0 with multi-queue support if missing.
if ! ip link show tap0 >/dev/null 2>&1; then
    ip tuntap add dev tap0 mode tap multi_queue user "$USER_NAME"
    ip addr add 10.20.30.1/24 dev tap0
fi
ip link set tap0 up

# (Re)start dnsmasq so it picks up tap0.
systemctl restart dnsmasq
