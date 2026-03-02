#!/usr/bin/env bash
# deploy-gcloud.sh — Deploy a unikernel to Google Cloud Compute Engine
#
# Prerequisites:
#   brew install google-cloud-sdk
#   gcloud auth login
#   gcloud config set project YOUR_PROJECT
#
# Usage:
#   ./scripts/deploy-gcloud.sh [name] [path-to-elf]
#
# This script:
#   1. Builds the unikernel (if no ELF path given)
#   2. Creates a bootable raw disk image with GRUB + multiboot2
#   3. Uploads to a GCS bucket
#   4. Creates a GCE custom image
#   5. Launches a VM instance with the image
#
# The VM uses a e2-micro instance with a virtio-net NIC (GCE default).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

NAME="${1:-unikernel-webserver}"
ELF="${2:-}"
ZONE="${UNIKERNEL_GCE_ZONE:-us-central1-a}"
MACHINE_TYPE="${UNIKERNEL_GCE_MACHINE:-e2-micro}"
BUCKET="${UNIKERNEL_GCS_BUCKET:-${NAME}-images}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
IMAGE_NAME="${NAME}-${TIMESTAMP}"
DISK_FILE="/tmp/${IMAGE_NAME}.raw"

# --- Resolve the project ID ---
PROJECT="$(gcloud config get-value project 2>/dev/null)"
if [ -z "$PROJECT" ]; then
    echo "Error: No GCP project set. Run: gcloud config set project YOUR_PROJECT"
    exit 1
fi

echo "==> GCP Project: $PROJECT"
echo "    Zone: $ZONE"
echo "    Machine: $MACHINE_TYPE"

# --- Build if needed ---
if [ -z "$ELF" ]; then
    echo "==> Building webserver..."
    cd "$PROJECT_ROOT"
    bazel build //apps/webserver:webserver.elf 2>&1
    ELF="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
fi

if [ ! -f "$ELF" ]; then
    echo "Error: ELF not found: $ELF"
    exit 1
fi

# --- Create a bootable raw disk image ---
# GCE requires a raw disk image with a valid partition table and GRUB bootloader.
# We create a minimal disk: MBR + ext2 partition + GRUB + kernel ELF.

echo "==> Creating bootable disk image..."

DISK_SIZE_MB=256

# Create sparse file
dd if=/dev/zero of="$DISK_FILE" bs=1M count=0 seek=$DISK_SIZE_MB 2>/dev/null

# If grub-mkrescue is available, create a proper bootable image
if command -v grub-mkrescue &>/dev/null; then
    ISODIR="$(mktemp -d)"
    mkdir -p "$ISODIR/boot/grub"
    cp "$ELF" "$ISODIR/boot/kernel.elf"
    cat > "$ISODIR/boot/grub/grub.cfg" <<'GRUB_EOF'
set timeout=0
set default=0
menuentry "unikernel" {
    multiboot2 /boot/kernel.elf
    boot
}
GRUB_EOF
    grub-mkrescue -o "$DISK_FILE" "$ISODIR" 2>/dev/null
    rm -rf "$ISODIR"
    echo "    Created bootable image with GRUB"
else
    # Fallback: raw image with kernel at offset 1MB (requires custom boot in cloud-init or PVH)
    echo "    Warning: grub-mkrescue not found. Creating raw image with embedded ELF."
    echo "    Install grub: brew install grub (or use a Linux build host)"
    dd if="$ELF" of="$DISK_FILE" bs=1M seek=1 conv=notrunc 2>/dev/null
fi

# GCE requires the image name to end in .raw and be tarred+gzipped
echo "==> Compressing disk image..."
TARBALL="/tmp/${IMAGE_NAME}.tar.gz"
cd /tmp
tar -czf "$TARBALL" "$(basename "$DISK_FILE")"

# --- Upload to GCS ---
echo "==> Ensuring GCS bucket exists: gs://$BUCKET"
gsutil ls "gs://$BUCKET" &>/dev/null || gsutil mb -l "${ZONE%-*}" "gs://$BUCKET"

echo "==> Uploading image to GCS..."
gsutil cp "$TARBALL" "gs://$BUCKET/${IMAGE_NAME}.tar.gz"

# --- Create GCE image ---
echo "==> Creating GCE image: $IMAGE_NAME"
gcloud compute images create "$IMAGE_NAME" \
    --source-uri="gs://$BUCKET/${IMAGE_NAME}.tar.gz" \
    --family="unikernel" \
    --guest-os-features=VIRTIO_SCSI_MULTIQUEUE \
    --project="$PROJECT" \
    --quiet

# --- Launch VM ---
echo "==> Launching VM instance: $NAME"
gcloud compute instances create "$NAME" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image="$IMAGE_NAME" \
    --image-project="$PROJECT" \
    --tags="http-server" \
    --metadata=serial-port-enable=TRUE \
    --project="$PROJECT" \
    --quiet 2>&1 || true

# --- Create firewall rule for HTTP ---
echo "==> Ensuring HTTP firewall rule..."
gcloud compute firewall-rules create allow-http-unikernel \
    --allow=tcp:80 \
    --target-tags=http-server \
    --project="$PROJECT" \
    --quiet 2>/dev/null || true

# --- Get external IP ---
EXTERNAL_IP="$(gcloud compute instances describe "$NAME" \
    --zone="$ZONE" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)' \
    --project="$PROJECT" 2>/dev/null)"

echo ""
echo "========================================="
echo "  Deployment complete!"
echo "========================================="
echo "  Instance: $NAME"
echo "  Zone:     $ZONE"
echo "  IP:       $EXTERNAL_IP"
echo "  URL:      http://$EXTERNAL_IP/"
echo ""
echo "  View serial console:"
echo "    gcloud compute instances get-serial-port-output $NAME --zone=$ZONE"
echo ""
echo "  SSH (for debugging):"
echo "    gcloud compute instances describe $NAME --zone=$ZONE"
echo ""
echo "  Cleanup:"
echo "    gcloud compute instances delete $NAME --zone=$ZONE --quiet"
echo "    gcloud compute images delete $IMAGE_NAME --quiet"
echo "    gsutil rm gs://$BUCKET/${IMAGE_NAME}.tar.gz"
echo "========================================="

# Cleanup local temp files
rm -f "$DISK_FILE" "$TARBALL"
