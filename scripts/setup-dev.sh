#!/usr/bin/env bash
# setup-dev.sh — Install all build/run dependencies on macOS
#
# Run this once before building or running the unikernel.

set -euo pipefail

echo "==> Checking for Homebrew..."
if ! command -v brew &>/dev/null; then
    echo "  Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

echo "==> Installing LLVM (clang, ld.lld, llvm-ar, llvm-nm)..."
brew install llvm

LLVM_PREFIX="$(brew --prefix llvm)"
echo "  LLVM installed at: $LLVM_PREFIX"

# Add LLVM to PATH for the current session and permanently
export PATH="$LLVM_PREFIX/bin:$PATH"

echo "  clang:  $(clang --version | head -1)"
echo "  ld.lld: $(ld.lld --version | head -1)"

echo "==> Installing Bazelisk (Bazel version manager)..."
brew install bazelisk

# Bazelisk is a wrapper that downloads the correct Bazel version automatically.
# We pin the version via .bazelversion.
echo "==> Creating .bazelversion..."
echo "7.3.1" > /Users/jitudas/github.com/r2jitu/unikernel/.bazelversion

echo "==> Installing QEMU (for local VM testing)..."
brew install qemu

echo "==> Installing GRUB (for creating bootable ISO images)..."
# grub for x86_64 on macOS
brew install grub 2>/dev/null || echo "  (grub may not be available via Homebrew on ARM — using raw ELF boot instead)"

echo ""
echo "========================================="
echo "  Setup complete!"
echo "========================================="
echo ""
echo "  Required: add LLVM to your PATH permanently."
echo "  Add this to your ~/.zshrc or ~/.bash_profile:"
echo ""
echo '    export PATH="'"$LLVM_PREFIX"'/bin:$PATH"'
echo ""
echo "  Then build and run the example web server:"
echo ""
echo "    cd $(cd "$(dirname "$0")/.." && pwd)"
echo "    bazel build //apps/webserver:webserver.elf"
echo "    ./scripts/run-local.sh"
echo ""
echo "  Access at: http://localhost:8080/"
echo "========================================="
