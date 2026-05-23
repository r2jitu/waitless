#!/usr/bin/env bash
# peer-deploy.sh — Provision a GCE VM running one of the Linux peers
# (nginx or tokio-hyper) for the waitless Pareto bench rig.
#
# Each peer VM is the Linux counterpart to `waitless-webserver`. Same
# machine type, same zone, same NIC class — the only difference is the
# software listening on :80 / :443. The bench harness drives all three
# (waitless / nginx / tokio-hyper) through `--env remote` with the
# appropriate `--target IP`, accumulating one JSONL row per cell.
#
# Native install (apt for nginx, scp + systemd for tokio-hyper). No
# Docker — Docker adds measurable overhead to the syscall hot path
# and would muddy the cost-breakdown chart.
#
# Idempotent: if the VM exists and is RUNNING, refreshes the config
# in-place and restarts the service. Otherwise creates it from
# scratch.
#
# Usage:
#   ./peer-deploy.sh --peer nginx --machine c3-highcpu-8
#   ./peer-deploy.sh --peer tokio-hyper --machine c3-highcpu-22 \
#       --name waitless-peer-tokio-22
#   ./peer-deploy.sh --peer nginx --delete
#
# Env: WAITLESS_GCE_PROJECT / WAITLESS_GCE_ZONE override the same vars
# deploy-gcloud.sh uses.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PEER=""
MACHINE="c3-highcpu-8"
NAME=""
DELETE=0
SPOT=1
while [ $# -gt 0 ]; do
    case "$1" in
    --peer)
        shift
        PEER="$1"
        ;;
    --machine)
        shift
        MACHINE="$1"
        ;;
    --name)
        shift
        NAME="$1"
        ;;
    --delete) DELETE=1 ;;
    --on-demand) SPOT=0 ;;
    -h | --help)
        sed -n '2,28p' "$0" | sed 's/^# *//'
        exit 0
        ;;
    *)
        echo "unknown arg: $1" >&2
        exit 1
        ;;
    esac
    shift
done

case "$PEER" in
nginx | tokio-hyper) ;;
*)
    echo "error: --peer must be 'nginx' or 'tokio-hyper'" >&2
    exit 1
    ;;
esac

[ -n "$NAME" ] || NAME="waitless-peer-${PEER//tokio-hyper/tokio}"

PROJECT="${WAITLESS_GCE_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
ZONE="${WAITLESS_GCE_ZONE:-us-west1-c}"
REGION="${ZONE%-*}"

[ -n "$PROJECT" ] || {
    echo "error: no GCP project set (env WAITLESS_GCE_PROJECT or gcloud config)" >&2
    exit 1
}

# ── Delete path ────────────────────────────────────────────────
if [ $DELETE -eq 1 ]; then
    echo "==> Deleting $NAME (zone $ZONE)..."
    gcloud compute instances delete "$NAME" --zone="$ZONE" \
        --project="$PROJECT" --quiet >/dev/null 2>&1 || true
    echo "    done."
    exit 0
fi

# ── Existence + state check ────────────────────────────────────
STATUS="$(gcloud compute instances describe "$NAME" --zone="$ZONE" \
    --project="$PROJECT" --format='value(status)' 2>/dev/null || echo MISSING)"

case "$STATUS" in
RUNNING)
    echo "==> $NAME is already RUNNING — refreshing config + restarting service..."
    NEEDS_CREATE=0
    ;;
TERMINATED | STOPPED)
    echo "==> $NAME is $STATUS — starting + refreshing config..."
    gcloud compute instances start "$NAME" --zone="$ZONE" --project="$PROJECT" >/dev/null
    NEEDS_CREATE=0
    ;;
MISSING)
    echo "==> $NAME does not exist — creating ($MACHINE in $ZONE)..."
    NEEDS_CREATE=1
    ;;
*)
    echo "==> $NAME in transient state '$STATUS' — waiting..."
    until [ "$(gcloud compute instances describe "$NAME" --zone="$ZONE" \
        --project="$PROJECT" --format='value(status)' 2>/dev/null)" = "RUNNING" ]; do
        sleep 3
    done
    NEEDS_CREATE=0
    ;;
esac

# ── Create the VM if needed ────────────────────────────────────
if [ $NEEDS_CREATE -eq 1 ]; then
    spot_flag=()
    [ $SPOT -eq 1 ] && spot_flag=(--provisioning-model=SPOT --instance-termination-action=STOP)

    # Debian 12 + gVNIC + matching the waitless deploy's networking
    # shape. Default VPC; firewall already opens 80/443 in most projects.
    gcloud compute instances create "$NAME" \
        --zone="$ZONE" \
        --project="$PROJECT" \
        --machine-type="$MACHINE" \
        --image-family=debian-12 \
        --image-project=debian-cloud \
        --network-interface=nic-type=GVNIC,network=default \
        --tags=http-server,https-server \
        "${spot_flag[@]}" \
        >/dev/null

    # SSH might not be up immediately. Wait.
    echo "    waiting for ssh..."
    for _ in $(seq 1 60); do
        if gcloud compute ssh "$NAME" --zone="$ZONE" --project="$PROJECT" \
            --command='true' >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
fi

# ── Common: tune sysctls for high-concurrency loadgen + server ──
#
# These match what gcp-deploy-bench.sh sets on the kvm-vm side, plus
# server-side caps (somaxconn, syn backlog, fd limits) that matter
# when N keep-alive conns climbs into 100K.
ssh_peer() {
    gcloud compute ssh "$NAME" --zone="$ZONE" --project="$PROJECT" \
        --command="$1"
}
scp_peer() {
    gcloud compute scp --zone="$ZONE" --project="$PROJECT" "$@"
}

echo "==> Tuning sysctls + fd limits on $NAME..."
ssh_peer "sudo tee /etc/sysctl.d/99-waitless-bench.conf >/dev/null <<'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
fs.file-max = 2097152
# Lower the privileged-port threshold so the tokio-hyper-peer non-root
# user can bind 80/443 directly. Avoids the systemd capability dance
# (file caps + AmbientCapabilities have subtle interaction bugs with
# User= that bit us). 80 instead of 1024: all ports >= 80 are now
# unprivileged. No security impact for a bench-only VM.
net.ipv4.ip_unprivileged_port_start = 80
EOF
sudo sysctl -p /etc/sysctl.d/99-waitless-bench.conf >/dev/null
sudo tee /etc/security/limits.d/99-waitless-bench.conf >/dev/null <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
EOF
"

# ── Peer-specific install + config ─────────────────────────────
if [ "$PEER" = "nginx" ]; then
    echo "==> Installing nginx + dropping config..."
    # Use the same nginx.conf we vetted in parity. Drop it into
    # /etc/nginx/nginx.conf and replace the default site config; nginx
    # on Debian splits config into nginx.conf + conf.d/. Our config is
    # self-contained, so we don't use conf.d.
    ssh_peer "sudo apt-get update -qq && sudo apt-get install -y -qq nginx >/dev/null"

    # Push nginx.conf + dev certs + static body files.
    scp_peer "$SCRIPT_DIR/nginx/nginx.conf" "$NAME:/tmp/nginx.conf" >/dev/null
    scp_peer "$REPO_ROOT/apps/webserver/dev_certs/dev_cert.pem" "$NAME:/tmp/dev_cert.pem" >/dev/null
    scp_peer "$REPO_ROOT/apps/webserver/dev_certs/dev_key.pem" "$NAME:/tmp/dev_key.pem" >/dev/null

    ssh_peer "sudo mv /tmp/nginx.conf /etc/nginx/nginx.conf
sudo mkdir -p /etc/nginx/tls /var/www/static
sudo mv /tmp/dev_cert.pem /etc/nginx/tls/dev_cert.pem
sudo mv /tmp/dev_key.pem /etc/nginx/tls/dev_key.pem
# scp + sudo mv preserves the uploader's ownership (jitudas) and mode
# 600; nginx runs as www-data and would get EACCES on key read at
# startup. Explicitly chown to root:www-data and chmod so www-data
# can read it but nobody else can.
sudo chown root:www-data /etc/nginx/tls/dev_cert.pem /etc/nginx/tls/dev_key.pem
sudo chmod 644 /etc/nginx/tls/dev_cert.pem
sudo chmod 640 /etc/nginx/tls/dev_key.pem
# Static body files — same content as the Docker image.
sudo dd if=/dev/zero of=/var/www/static/static-16k bs=1024 count=16 status=none
sudo dd if=/dev/zero of=/var/www/static/static-64k bs=1024 count=64 status=none
sudo dd if=/dev/zero of=/var/www/static/static-256k bs=1024 count=256 status=none
sudo dd if=/dev/zero of=/var/www/static/static-1m bs=1024 count=1024 status=none
printf '%s' '{\"status\":\"ok\",\"runtime\":\"waitless\",\"version\":\"0.1.0\"}' | sudo tee /var/www/static/health.json >/dev/null
# nginx on Debian's systemd unit has a per-process LimitNOFILE of
# 1024 by default — way too low for 65K worker_connections × N
# workers. Bump it via a drop-in override.
sudo mkdir -p /etc/systemd/system/nginx.service.d
sudo tee /etc/systemd/system/nginx.service.d/limits.conf >/dev/null <<'EOF'
[Service]
LimitNOFILE=1048576
EOF
sudo systemctl daemon-reload
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx >/dev/null
"

else # tokio-hyper
    echo "==> Building tokio-hyper-peer for x86_64-linux..."
    # Build locally if cargo is available + target is installed;
    # otherwise build on the peer VM itself. Local build is faster
    # (one-time toolchain install) but cross-compiling rustls + ring
    # to x86_64-linux from arm64-macos needs cross or a docker
    # builder, which adds complexity. Pragmatic v1: build on the peer.
    ssh_peer "command -v cargo >/dev/null 2>&1 || (
    echo '  installing rustup + cargo on $NAME...'
    sudo apt-get update -qq && sudo apt-get install -y -qq curl build-essential pkg-config >/dev/null
    curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal >/dev/null
)
"
    # Push the source (excluding target/).
    tar --exclude=target --exclude=Cargo.lock -C "$SCRIPT_DIR" -czf /tmp/peer-tokio-src.tar.gz tokio-hyper
    scp_peer /tmp/peer-tokio-src.tar.gz "$NAME:/tmp/" >/dev/null
    rm -f /tmp/peer-tokio-src.tar.gz

    scp_peer "$REPO_ROOT/apps/webserver/dev_certs/dev_cert.pem" "$NAME:/tmp/dev_cert.pem" >/dev/null
    scp_peer "$REPO_ROOT/apps/webserver/dev_certs/dev_key.pem" "$NAME:/tmp/dev_key.pem" >/dev/null

    ssh_peer "set -e
rm -rf /tmp/peer-tokio-src
mkdir /tmp/peer-tokio-src
tar -xzf /tmp/peer-tokio-src.tar.gz -C /tmp/peer-tokio-src
cd /tmp/peer-tokio-src/tokio-hyper
source \$HOME/.cargo/env
cargo build --release 2>&1 | tail -3
sudo install -m 755 target/release/tokio-hyper-peer /usr/local/bin/tokio-hyper-peer
sudo mkdir -p /etc/tokio-hyper/tls
sudo mv /tmp/dev_cert.pem /etc/tokio-hyper/tls/dev_cert.pem
sudo mv /tmp/dev_key.pem /etc/tokio-hyper/tls/dev_key.pem
# scp + sudo mv preserves the uploader's ownership (jitudas) and mode
# 600; tokiopeer would get EACCES on key read at startup. Chown to
# the user the service will run as.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tokiopeer 2>/dev/null || true
sudo chown tokiopeer:tokiopeer /etc/tokio-hyper/tls/dev_cert.pem /etc/tokio-hyper/tls/dev_key.pem
sudo chmod 644 /etc/tokio-hyper/tls/dev_cert.pem
sudo chmod 600 /etc/tokio-hyper/tls/dev_key.pem

# systemd unit. Bind 80/443/8080 as non-root (tokiopeer).
# net.ipv4.ip_unprivileged_port_start=80 is set in the sysctls block
# above, so privileged-port bind no longer requires CAP_NET_BIND_SERVICE.
sudo tee /etc/systemd/system/tokio-hyper-peer.service >/dev/null <<'EOF'
[Unit]
Description=tokio-hyper-peer (waitless bench peer)
After=network.target

[Service]
Type=simple
User=tokiopeer
ExecStart=/usr/local/bin/tokio-hyper-peer --upstream-port 0
LimitNOFILE=1048576
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl restart tokio-hyper-peer
sudo systemctl enable tokio-hyper-peer >/dev/null
"
fi

# ── Health-check ───────────────────────────────────────────────
INTERNAL_IP="$(gcloud compute instances describe "$NAME" --zone="$ZONE" \
    --project="$PROJECT" --format='value(networkInterfaces[0].networkIP)')"

echo "==> Health-check ($PEER on $INTERNAL_IP)..."
for _ in $(seq 1 30); do
    if ssh_peer "curl -fsSk --max-time 2 http://localhost/health >/dev/null"; then
        echo "    /health OK"
        break
    fi
    sleep 1
done

# TLS too — confirms cert + key wired correctly. -k skips verify
# (self-signed dev cert).
if ssh_peer "curl -fsSk --max-time 2 https://localhost/health >/dev/null"; then
    echo "    /health OK over TLS"
else
    echo "    WARNING: /health failed over TLS — check service logs:"
    if [ "$PEER" = nginx ]; then
        ssh_peer "sudo journalctl -u nginx --no-pager -n 20"
    else
        ssh_peer "sudo journalctl -u tokio-hyper-peer --no-pager -n 20"
    fi
    exit 1
fi

echo ""
echo "==> $NAME ready."
echo "    peer:        $PEER"
echo "    machine:     $MACHINE"
echo "    internal IP: $INTERNAL_IP"
echo "    bench:       python3 bench.py --env remote --target $INTERNAL_IP ..."
