#!/usr/bin/env bash
# scripts/make-limine-iso.sh — Create a Limine-bootable ISO from a kernel ELF.
#
# Usage: make-limine-iso.sh <kernel.elf> <output.iso> [--arch aarch64|x86_64] [--conf limine.conf]
#
# Prerequisites: xorriso (brew install xorriso), git
# Limine binaries are cloned/cached in .cache/limine/ on first run.

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

KERNEL_ELF=""
OUTPUT_ISO=""
ARCH="x86_64"
LIMINE_CONF=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="$2"; shift 2 ;;
        --conf) LIMINE_CONF="$2"; shift 2 ;;
        *) if [[ -z "$KERNEL_ELF" ]]; then KERNEL_ELF="$1"
           elif [[ -z "$OUTPUT_ISO" ]]; then OUTPUT_ISO="$1"
           fi; shift ;;
    esac
done

[[ -n "$KERNEL_ELF" ]] || die "Usage: $0 <kernel.elf> <output.iso> [--arch x86_64|aarch64] [--conf limine.conf]"
[[ -n "$OUTPUT_ISO" ]] || die "Usage: $0 <kernel.elf> <output.iso> [--arch x86_64|aarch64] [--conf limine.conf]"
[[ -f "$KERNEL_ELF" ]] || die "Kernel ELF not found: $KERNEL_ELF"

command -v xorriso >/dev/null 2>&1 || die "xorriso not found. Install: brew install xorriso"
command -v git >/dev/null 2>&1 || die "git not found"

# Find project root (works standalone, bazel run, and bazel genrule)
if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then
    PROJECT_ROOT="$BUILD_WORKSPACE_DIRECTORY"
elif PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    : # git found it
else
    PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi

# Default limine.conf location
if [[ -z "$LIMINE_CONF" ]]; then
    LIMINE_CONF="$PROJECT_ROOT/boot/limine.conf"
fi
[[ -f "$LIMINE_CONF" ]] || die "limine.conf not found: $LIMINE_CONF"

# --- Fetch Limine binaries (cached in project root) ---
#
# Multiple `*.iso` genrules can run in parallel (one per app) and
# they all point at the same cache dir, so the fetch + build steps
# need a cross-process lock. `mkdir` is atomic on every POSIX
# filesystem — first caller wins the directory, others spin on its
# existence. macOS has no `flock(1)`, so we can't use that.
LIMINE_DIR="$PROJECT_ROOT/.cache/limine"
LIMINE_LOCK="$PROJECT_ROOT/.cache/.limine.lock"
mkdir -p "$PROJECT_ROOT/.cache"

ISO_ROOT=""
cleanup() {
    rmdir "$LIMINE_LOCK" 2>/dev/null || true
    [[ -n "$ISO_ROOT" ]] && rm -rf "$ISO_ROOT"
}
trap cleanup EXIT

while ! mkdir "$LIMINE_LOCK" 2>/dev/null; do sleep 0.2; done

if [[ ! -d "$LIMINE_DIR" ]]; then
    echo "[ISO] Fetching Limine bootloader..."
    git clone --depth=1 --branch=v8.x-binary \
        https://github.com/limine-bootloader/limine.git "$LIMINE_DIR" 2>/dev/null
fi

# Build the limine CLI tool (needed for BIOS install on ISO)
if [[ ! -f "$LIMINE_DIR/limine" ]]; then
    echo "[ISO] Building limine CLI tool..."
    make -C "$LIMINE_DIR" 2>/dev/null
fi

rmdir "$LIMINE_LOCK" 2>/dev/null || true

# --- Create ISO directory structure ---
ISO_ROOT=$(mktemp -d)

mkdir -p "$ISO_ROOT/boot/limine"
mkdir -p "$ISO_ROOT/EFI/BOOT"

# Copy kernel
cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel.elf"

# Copy Limine config
cp "$LIMINE_CONF" "$ISO_ROOT/boot/limine/limine.conf"

# Copy Limine bootloader files
cp "$LIMINE_DIR/limine-bios.sys" "$ISO_ROOT/boot/limine/" 2>/dev/null || true
cp "$LIMINE_DIR/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/" 2>/dev/null || true
cp "$LIMINE_DIR/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/" 2>/dev/null || true

# Copy UEFI bootloader (arch-specific)
if [[ "$ARCH" == "aarch64" ]]; then
    cp "$LIMINE_DIR/BOOTAA64.EFI" "$ISO_ROOT/EFI/BOOT/" 2>/dev/null || true
else
    cp "$LIMINE_DIR/BOOTX64.EFI" "$ISO_ROOT/EFI/BOOT/" 2>/dev/null || true
fi

# --- Build ISO ---
echo "[ISO] Creating Limine ISO..."

XORRISO_ARGS=(
    -as mkisofs
    -R -J  # Rock Ridge + Joliet extensions
)

# BIOS boot (El Torito) — only for x86_64
if [[ "$ARCH" == "x86_64" && -f "$ISO_ROOT/boot/limine/limine-bios-cd.bin" ]]; then
    XORRISO_ARGS+=(
        -b boot/limine/limine-bios-cd.bin
        -no-emul-boot -boot-load-size 4 -boot-info-table
    )
fi

# UEFI boot (El Torito)
if [[ -f "$ISO_ROOT/boot/limine/limine-uefi-cd.bin" ]]; then
    XORRISO_ARGS+=(
        --efi-boot boot/limine/limine-uefi-cd.bin
        -efi-boot-part --efi-boot-image
    )
fi

XORRISO_ARGS+=(
    --protective-msdos-label
    "$ISO_ROOT" -o "$OUTPUT_ISO"
)

xorriso "${XORRISO_ARGS[@]}" 2>/dev/null

# Install BIOS bootloader on the ISO (x86_64 only).
# chmod +w needed because Bazel genrule output files may be read-only.
if [[ "$ARCH" == "x86_64" && -x "$LIMINE_DIR/limine" ]]; then
    chmod +w "$OUTPUT_ISO" 2>/dev/null || true
    "$LIMINE_DIR/limine" bios-install "$OUTPUT_ISO" 2>/dev/null || true
fi

echo "[ISO] Created: $OUTPUT_ISO"
ls -lh "$OUTPUT_ISO"
