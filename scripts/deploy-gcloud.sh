#!/usr/bin/env bash
# deploy-gcloud.sh — Deploy the unikernel as a GCE custom image.
#
# Builds //apps/webserver:webserver.iso (Limine hybrid BIOS+UEFI ISO),
# wraps it as a GCE-compatible disk.raw.tar.gz, uploads to GCS, creates
# a custom image, and launches a VM with serial-port logging enabled.
#
# The Limine hybrid ISO boots unchanged on GCE SeaBIOS: the protective
# MBR written by `limine bios-install` is a valid boot sector, so the
# ISO functions as a raw disk image (isohybrid-style). UEFI_COMPATIBLE
# is tagged on the image so OVMF-backed machine types also work.
#
# Prerequisites:
#   brew install google-cloud-sdk xorriso
#   gcloud auth login && gcloud config set project YOUR_PROJECT
#
# Usage:
#   ./scripts/deploy-gcloud.sh build-only   # build disk.raw locally; stop
#   ./scripts/deploy-gcloud.sh qemu-test    # build + boot in local QEMU
#   ./scripts/deploy-gcloud.sh deploy       # full deploy (default)
#   ./scripts/deploy-gcloud.sh serial       # one-shot dump of serial port 1
#   ./scripts/deploy-gcloud.sh logs         # follow serial port of current VM
#   ./scripts/deploy-gcloud.sh status       # show instance state + external IP
#   ./scripts/deploy-gcloud.sh stop         # stop the VM (preserves disk)
#   ./scripts/deploy-gcloud.sh start        # start a stopped VM
#   ./scripts/deploy-gcloud.sh ip           # print current external IP
#   ./scripts/deploy-gcloud.sh delete       # delete the VM (keeps image)
#   ./scripts/deploy-gcloud.sh clean-stale  # remove orphan images + tarballs
#                                           #   (leftovers from timestamped names)
#   ./scripts/deploy-gcloud.sh purge        # delete VM + image + all GCS objects
#
# Each deploy overwrites the previous image and tarball in place
# (single stable name + GCE image delete-then-create), so nothing
# accumulates across deploys.
#
# Env overrides:
#   WAITLESS_GCE_PROJECT, WAITLESS_GCE_ZONE, WAITLESS_GCE_MACHINE,
#   WAITLESS_GCS_BUCKET, WAITLESS_GCE_NAME
#   WAITLESS_GCE_ADDRESS — name of a reserved regional static IP to
#     attach to the instance (`gcloud compute addresses create`).
#     Unset → an ephemeral IP. A public site wants a reserved one so
#     the DNS A-record survives restarts / preemption.
#   WAITLESS_BAZEL_DEFINES — extra flags appended to the ISO build,
#     e.g. `--define tls_cert=prod` to bake in the production TLS
#     cert. `scripts/renew-and-deploy.sh` sets this.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="${1:-deploy}"

NAME="${WAITLESS_GCE_NAME:-waitless-webserver}"
# Default zone us-west1-c: only us-west1 zone with c3-highcpu-8.
ZONE="${WAITLESS_GCE_ZONE:-us-west1-c}"
# c3-highcpu-8 by default: 8 vCPU room for multi-core bench scaling.
# (Both c3 and n2 negotiate `GqiQpl` from the gVNIC device on the
# GCE images we've tested — DQO_RDA is on the c3 menu in principle
# but isn't advertised in our deploy path.) Override with
# `WAITLESS_GCE_MACHINE=n2-highcpu-8` to bench the older NIC class
# on the same gve driver.
MACHINE_TYPE="${WAITLESS_GCE_MACHINE:-c3-highcpu-8}"
BUCKET="${WAITLESS_GCS_BUCKET:-${NAME}-images}"

# Single-slot deploy: the image / tarball / workdir all use stable
# names, so each deploy just overwrites the previous one. GCE images
# are immutable, so we delete-before-create to update in place; GCS
# objects just get overwritten by `gsutil cp`. Avoids the
# unbounded-history accumulation you get with timestamped names.
IMAGE_NAME="${NAME}-image"
TARBALL_NAME="disk.raw.tar.gz"
WORKDIR="/tmp/${NAME}-deploy"
DISK_FILE="${WORKDIR}/disk.raw"
TARBALL="${WORKDIR}/${TARBALL_NAME}"

PROJECT="${WAITLESS_GCE_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"

_require_project() {
    if [ -z "$PROJECT" ]; then
        echo "Error: no GCP project set (env WAITLESS_GCE_PROJECT or gcloud config)" >&2
        exit 1
    fi
}

# --- Build disk.raw from the Limine ISO ---
# GCE expects a tarball containing a single file named exactly "disk.raw"
# at the tar root, sized to a whole number of GB (>= 1 GB).
build_disk() {
    echo "==> Building //apps/webserver:webserver_iso_x86_64 ..."
    cd "$PROJECT_ROOT"
    # The iso variant's transition pins the target platform
    # regardless of the host default, so arm64 dev hosts still
    # produce an x86 ISO that GCE's x86 machine types can boot.
    # For ARM GCE / Graviton deployment, swap to `:webserver_iso_aarch64`.
    #
    # WAITLESS_BAZEL_DEFINES carries optional extra flags (e.g.
    # `--define tls_cert=prod`); unquoted so multi-word values split.
    # shellcheck disable=SC2086
    bazel build //apps/webserver:webserver_iso_x86_64 ${WAITLESS_BAZEL_DEFINES:-}
    local iso="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver_iso_x86_64.iso"
    [ -f "$iso" ] || {
        echo "ERROR: ISO not produced: $iso" >&2
        exit 1
    }

    rm -rf "$WORKDIR"
    mkdir -p "$WORKDIR"
    cp "$iso" "$DISK_FILE"
    chmod u+w "$DISK_FILE"
    # GCE's custom-image importer requires: uncompressed disk.raw
    # size >= 10 GiB, as a multiple of 1 GiB. Learned on 2026-04-16:
    # 1 GiB (or no pad at all) both get rejected with
    # "The tar archive is not a valid image." 10 GiB works. The
    # padding is pure zeroes and compresses to nothing, so the
    # uploaded tarball stays small (~1 MB).
    truncate -s 10G "$DISK_FILE"

    echo "==> Packaging ${TARBALL_NAME} (disk.raw at tar root)..."
    # GCE's custom-image importer wants a GNU-format tar with a single
    # sparse disk.raw at the root. macOS BSD tar only produces PAX or
    # ustar (no `--format=gnu` / `oldgnu`), and its PAX output carries
    # `PaxHeader/…` entries GCE rejects. Python's stdlib tarfile can
    # emit GNU format directly and handles sparse-encoding correctly,
    # so we drive the packaging from a small inline script instead of
    # tar(1).
    #
    # gzip level 1 instead of the default 9: disk.raw is mostly
    # zeroes (padded to 10 GiB), which level-1 compresses just as
    # effectively as level-9 for our purposes (~1 MB on the wire
    # either way) but in ~1 s vs ~5 s. Iteration-speed win — the
    # ~4 s saved here is reclaimed for every redeploy.
    python3 - "$WORKDIR" "$TARBALL" <<'PY'
import gzip, os, sys, tarfile
workdir, out = sys.argv[1], sys.argv[2]
with gzip.GzipFile(out, "wb", compresslevel=1) as gz:
    with tarfile.TarFile(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as t:
        t.add(os.path.join(workdir, "disk.raw"), arcname="disk.raw")
PY

    echo "    Disk:    $DISK_FILE ($(du -h "$DISK_FILE" | awk '{print $1}') on-disk)"
    echo "    Tarball: $TARBALL ($(du -h "$TARBALL" | awk '{print $1}'))"
}

# --- Local QEMU smoke test ---
# Boots the same disk.raw we're about to upload, so any boot failure
# surfaces here instead of on GCE. SeaBIOS + virtio-net-pci + virtio-blk
# matches the GCE hardware profile closely enough that a successful boot
# here is a strong signal.
qemu_test() {
    if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
        echo "ERROR: qemu-system-x86_64 not found; install via 'brew install qemu'" >&2
        exit 1
    fi
    echo "==> Booting disk.raw in QEMU (Ctrl-a x to exit)..."
    # -cpu max is load-bearing: the p256 + chacha20poly1305 crates use
    # AVX / BMI2 intrinsics. QEMU's default qemu64 CPU omits both, so
    # the TLS cert parse at boot fires #UD on VMOVUPS/MULX. Real GCP
    # hardware (Skylake+) has these features natively.
    qemu-system-x86_64 \
        -cpu max \
        -machine q35 -m 256 -nographic \
        -drive if=virtio,format=raw,file="$DISK_FILE" \
        -netdev user,id=n0,hostfwd=tcp::18080-:80,hostfwd=tcp::18443-:443 \
        -device virtio-net-pci,netdev=n0 \
        -serial mon:stdio
}

# --- Upload + image create + VM launch ---
#
# Deploy DAG (overlaps the independent operations instead of running
# strictly sequentially):
#
#   upload  ┐
#   img-del ┼── wait → images create ──┐
#   vm-del  ┘                          │
#           └──────── still running ───┤
#                                     wait → instances create
#
# `images create` is a ~2 min GCP-backend import we can't shrink from
# the guest side; everything else is <30 s. Overlapping VM delete
# with image create saves the one chunk of wall time we have control
# over. The old VM's boot disk was cloned from the old image at
# instance-create time, so tearing them down concurrently is safe.
# For fast local iteration use `scripts/gcp.sh serve` — it pushes the
# ELF to kvm-vm and reloads in ~5 s.
deploy() {
    _require_project
    echo "==> GCP project: $PROJECT   zone: $ZONE   machine: $MACHINE_TYPE"

    echo "==> Ensuring GCS bucket: gs://$BUCKET"
    gsutil ls "gs://$BUCKET" >/dev/null 2>&1 ||
        gsutil mb -l "${ZONE%-*}" "gs://$BUCKET"

    # Fire the three independent teardown / upload operations in
    # parallel. All are idempotent and safe to run unconditionally.
    # (Image create is the ~2 min GCP backend import step — nothing
    # we can do guest-side to shrink it; we at least overlap VM
    # delete with it below.)
    echo "==> Upload + cleanup (parallel) ..."
    (
        gsutil -q cp "$TARBALL" "gs://$BUCKET/${TARBALL_NAME}" &&
            echo "    upload: done"
    ) &
    local upload_pid=$!
    (
        gcloud compute instances delete "$NAME" \
            --zone="$ZONE" --project="$PROJECT" --quiet \
            >/dev/null 2>&1 &&
            echo "    vm delete: done" ||
            echo "    vm delete: (not present)"
    ) &
    local vm_del_pid=$!
    (
        gcloud compute images delete "$IMAGE_NAME" \
            --project="$PROJECT" --quiet \
            >/dev/null 2>&1 &&
            echo "    image delete: done" ||
            echo "    image delete: (not present)"
    ) &
    local img_del_pid=$!

    # Image create waits only for upload + old-image-gone; VM delete
    # keeps running in parallel with image creation.
    wait "$upload_pid" "$img_del_pid"

    # UEFI_COMPATIBLE lets the image boot on OVMF-backed machine types
    # (c3, t2a, anything Arm). GVNIC advertises the image as
    # gVNIC-capable so instances can be launched with --nic-type=GVNIC
    # without GCE rejecting it; setting it unconditionally is safe
    # even for virtio-net deployments (GCE just ignores the flag when
    # the instance doesn't request GVNIC). The Limine ISO carries
    # both BIOS and UEFI bootloaders, so it boots either way.
    echo "==> Creating GCE image: $IMAGE_NAME"
    gcloud compute images create "$IMAGE_NAME" \
        --source-uri="gs://$BUCKET/${TARBALL_NAME}" \
        --family=waitless \
        --guest-os-features=UEFI_COMPATIBLE,GVNIC \
        --project="$PROJECT" \
        --quiet

    # Instance create needs the old VM gone too.
    wait "$vm_del_pid"

    echo "==> Launching VM: $NAME"
    # NIC selection: gVNIC (default) or legacy virtio-net (LEGACY_VIRTIO_NIC=1).
    #
    # gVNIC is Google's own NIC format; real Toeplitz RSS spreads
    # 4-tuples across queues so Tier 1 multi-queue actually uses all
    # cores. The `nic-type=GVNIC` flag switches the vNIC backend;
    # the image carries the GVNIC guest-os-feature (set on image
    # create above). See reference_gce_gvnic.md.
    #
    # virtio-net on GCE is strictly legacy v0.95 (no modern PCI caps,
    # can't negotiate VIRTIO_F_VERSION_1). Legacy MQ activates but
    # GCE's Andromeda backend doesn't actually hash RX across queues
    # for virtio — all flows land on qp 0 (see
    # reference_gce_legacy_mq.md). Kept behind LEGACY_VIRTIO_NIC=1
    # for A/B comparison only.
    #
    # QUEUE_COUNT: number of RX+TX queue pairs to request from the
    # vNIC backend. Should match the guest's vCPU count so each
    # core owns a queue pair under Tier 1. Default 8 to match the
    # default c3-highcpu-8 machine type (and the upper limit gVNIC
    # honours per instance); override for other sizes.
    local qc="${QUEUE_COUNT:-8}"
    local nic_args
    if [[ "${LEGACY_VIRTIO_NIC:-}" == "1" ]]; then
        echo "    (using legacy virtio-net, queue-count=${qc} — RX pins to qp0 on GCE)"
        nic_args="queue-count=${qc}"
    else
        echo "    (using gVNIC, queue-count=${qc})"
        nic_args="nic-type=GVNIC,queue-count=${qc}"
    fi
    # Spot/preemptible provisioning (default on). Spot VMs draw from
    # a separate capacity pool than standard on-demand, so when a
    # zone reports "no resources" for the on-demand pool (`us-west1-a`
    # has been a chronic offender for n2-highcpu-4 since this script
    # was written), spot can place the VM anyway. Trade-off: spot
    # VMs can be reclaimed with 30 s notice at any time — fine for
    # short bench runs and dev iteration, not for steady serving.
    # `kvm-vm` is already spot for the same reason. Set
    # `WAITLESS_GCE_PREEMPTIBLE=0` for on-demand provisioning if
    # you need uninterruptible runs. The flag adds
    # `--provisioning-model=SPOT` plus the required
    # `--no-restart-on-failure` / `--maintenance-policy=TERMINATE`
    # companions.
    local preempt_args=()
    if [[ "${WAITLESS_GCE_PREEMPTIBLE:-1}" == "1" ]]; then
        echo "    (preemptible / SPOT provisioning)"
        preempt_args=(
            --provisioning-model=SPOT
            --no-restart-on-failure
            --maintenance-policy=TERMINATE
        )
    fi
    # Optional reserved static external IP. WAITLESS_GCE_ADDRESS names
    # a regional address reserved with `gcloud compute addresses
    # create`; resolve it to its IP and pin it on the NIC. Unset → an
    # ephemeral IP.
    local net_iface="network=default,${nic_args}"
    if [ -n "${WAITLESS_GCE_ADDRESS:-}" ]; then
        local static_ip
        static_ip="$(gcloud compute addresses describe "$WAITLESS_GCE_ADDRESS" \
            --region="${ZONE%-*}" --project="$PROJECT" \
            --format='value(address)' 2>/dev/null || true)"
        if [ -z "$static_ip" ]; then
            echo "Error: reserved address '$WAITLESS_GCE_ADDRESS' not found in" \
                "region ${ZONE%-*}" >&2
            exit 1
        fi
        echo "    (static IP: $WAITLESS_GCE_ADDRESS = $static_ip)"
        net_iface="${net_iface},address=${static_ip}"
    fi
    gcloud compute instances create "$NAME" \
        --zone="$ZONE" \
        --machine-type="$MACHINE_TYPE" \
        --image="$IMAGE_NAME" \
        --image-project="$PROJECT" \
        --network-interface="$net_iface" \
        --tags=http-server \
        --metadata=serial-port-enable=TRUE \
        ${preempt_args[@]+"${preempt_args[@]}"} \
        --project="$PROJECT" \
        --quiet

    # udp:443 is load-bearing: HTTP/3 is QUIC over UDP. Without it the
    # h3 listener is unreachable and Chrome silently falls back to TCP
    # (`firewall-rules create` is a no-op if the rule already exists —
    # an existing rule must be `update`d to add the port).
    gcloud compute firewall-rules create allow-http-waitless \
        --allow=tcp:80,tcp:443,udp:443 \
        --target-tags=http-server \
        --project="$PROJECT" \
        --quiet 2>/dev/null || true

    local ip
    ip="$(gcloud compute instances describe "$NAME" \
        --zone="$ZONE" --project="$PROJECT" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"

    cat <<EOF

=========================================
  Deployment complete!
=========================================
  Instance: $NAME   Zone: $ZONE   IP: $ip
  URL:      http://$ip/

  Tail serial console (first boot messages go here):
    gcloud compute instances get-serial-port-output $NAME \\
        --zone=$ZONE --project=$PROJECT

  Or via this script:
    $0 logs

  Cleanup:
    gcloud compute instances delete $NAME --zone=$ZONE --project=$PROJECT --quiet
    gcloud compute images delete $IMAGE_NAME --project=$PROJECT --quiet
    gsutil rm gs://$BUCKET/${TARBALL_NAME}
=========================================
EOF
}

read_serial() {
    _require_project
    gcloud compute instances get-serial-port-output "$NAME" \
        --zone="$ZONE" --project="$PROJECT"
}

tail_serial() {
    _require_project
    echo "==> Following serial port 1 of $NAME (Ctrl-C to stop)..." >&2
    local start=0
    while true; do
        local out
        out="$(gcloud compute instances get-serial-port-output "$NAME" \
            --zone="$ZONE" --project="$PROJECT" --start="$start" 2>/dev/null || true)"
        if [ -n "$out" ]; then
            printf '%s' "$out"
            start=$((start + ${#out}))
        fi
        sleep 2
    done
}

show_status() {
    _require_project
    gcloud compute instances describe "$NAME" \
        --zone="$ZONE" --project="$PROJECT" \
        --format='table(name,status,machineType.basename(),networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP)' \
        2>&1 || echo "(instance not found)"
}

show_ip() {
    _require_project
    gcloud compute instances describe "$NAME" \
        --zone="$ZONE" --project="$PROJECT" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null
}

stop_vm() {
    _require_project
    echo "==> Stopping $NAME..."
    gcloud compute instances stop "$NAME" \
        --zone="$ZONE" --project="$PROJECT" --quiet
}

start_vm() {
    _require_project
    echo "==> Starting $NAME..."
    gcloud compute instances start "$NAME" \
        --zone="$ZONE" --project="$PROJECT" --quiet
    local ip
    ip="$(show_ip)"
    echo "    External IP: $ip   URL: http://$ip/"
}

# Delete the VM only. Keeps images so you can redeploy without
# rebuilding + reuploading; keeps the firewall rule so a later
# `deploy` doesn't need to recreate it.
delete_vm() {
    _require_project
    echo "==> Deleting instance $NAME..."
    gcloud compute instances delete "$NAME" \
        --zone="$ZONE" --project="$PROJECT" --quiet 2>&1 ||
        echo "(instance already gone)"
}

# Sweep out orphaned images + tarballs from the old timestamped-name
# scheme. After switching to stable names, anything not matching
# $IMAGE_NAME / $TARBALL_NAME is leftover junk. Safe to run any time;
# a live VM references its own cloned disk, not the image, so deleting
# stale images doesn't affect running instances.
clean_stale() {
    _require_project
    echo "==> Cleaning stale images + GCS objects in $PROJECT..."

    local stale_images
    stale_images="$(gcloud compute images list \
        --filter="family=waitless AND name!=$IMAGE_NAME" \
        --format='value(name)' --project="$PROJECT" 2>/dev/null)"
    if [ -n "$stale_images" ]; then
        local n
        n=$(echo "$stale_images" | wc -l | tr -d ' ')
        echo "    deleting $n stale image(s)"
        # shellcheck disable=SC2086
        gcloud compute images delete $stale_images \
            --project="$PROJECT" --quiet
    else
        echo "    no stale images"
    fi

    if gsutil ls "gs://$BUCKET" >/dev/null 2>&1; then
        local stale_objs
        stale_objs="$(gsutil ls "gs://$BUCKET/" 2>/dev/null |
            grep -v "/${TARBALL_NAME}\$" || true)"
        if [ -n "$stale_objs" ]; then
            local n
            n=$(echo "$stale_objs" | wc -l | tr -d ' ')
            echo "    deleting $n stale GCS object(s)"
            # shellcheck disable=SC2086
            gsutil -m rm $stale_objs
        else
            echo "    no stale GCS objects"
        fi
    fi
}

# Full teardown: VM, every image in the `waitless` family, every
# tarball in the GCS bucket, and the firewall rule. Intended for
# "I'm done with this experiment, zero it all out."
purge() {
    _require_project
    echo "==> Purging VM, images, bucket, and firewall rule in $PROJECT..."

    gcloud compute instances delete "$NAME" \
        --zone="$ZONE" --project="$PROJECT" --quiet 2>/dev/null &&
        echo "    instance: deleted" ||
        echo "    instance: (not present)"

    # Delete every image in the waitless family. `--filter` keeps us
    # from nuking unrelated images that happen to live in the same
    # project.
    local images
    images="$(gcloud compute images list \
        --filter="family=waitless" \
        --format='value(name)' --project="$PROJECT" 2>/dev/null)"
    if [ -n "$images" ]; then
        # shellcheck disable=SC2086
        gcloud compute images delete $images --project="$PROJECT" --quiet
        echo "    images:   deleted $(echo "$images" | wc -l | tr -d ' ')"
    else
        echo "    images:   (none)"
    fi

    if gsutil ls "gs://$BUCKET" >/dev/null 2>&1; then
        gsutil -m rm -r "gs://$BUCKET" 2>/dev/null || true
        echo "    bucket:   deleted gs://$BUCKET"
    else
        echo "    bucket:   (not present)"
    fi

    gcloud compute firewall-rules delete allow-http-waitless \
        --project="$PROJECT" --quiet 2>/dev/null &&
        echo "    firewall: deleted" ||
        echo "    firewall: (not present)"
}

case "$MODE" in
build-only) build_disk ;;
qemu-test)
    build_disk
    qemu_test
    ;;
deploy)
    build_disk
    deploy
    ;;
serial) read_serial ;;
logs) tail_serial ;;
status) show_status ;;
ip) show_ip ;;
stop) stop_vm ;;
start) start_vm ;;
delete) delete_vm ;;
clean-stale) clean_stale ;;
purge) purge ;;
*)
    echo "Usage: $0 {build-only|qemu-test|deploy|serial|logs|status|ip|stop|start|delete|clean-stale|purge}" >&2
    exit 1
    ;;
esac
