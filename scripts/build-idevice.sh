#!/usr/bin/env bash
# Builds the idevice FFI static library for iOS (arm64) from upstream source
# and installs it into Vendor/idevice/. Requires macOS with Xcode + rustup.
#
# The upstream commit is pinned in Vendor/idevice/UPSTREAM_COMMIT.
# Override with: IDEVICE_REF=<sha-or-branch> scripts/build-idevice.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/Vendor/idevice"
SRC="${IDEVICE_SRC:-$ROOT/Vendor/idevice-build/idevice}"
REF="${IDEVICE_REF:-$(tr -d '[:space:]' < "$VENDOR/UPSTREAM_COMMIT")}"

if [ ! -d "$SRC/.git" ]; then
  git clone https://github.com/jkcoxson/idevice.git "$SRC"
fi
git -C "$SRC" fetch --quiet origin
git -C "$SRC" checkout --quiet --detach "$REF"
echo "Building idevice at $(git -C "$SRC" rev-parse HEAD)"

rustup target add aarch64-apple-ios

cd "$SRC/ffi"
BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$(xcrun --sdk iphoneos --show-sdk-path)" \
IPHONEOS_DEPLOYMENT_TARGET=18.0 \
  cargo build --release --target aarch64-apple-ios

# build.rs regenerates ffi/idevice.h with cbindgen during the build.
cp "$SRC/target/aarch64-apple-ios/release/libidevice_ffi.a" "$VENDOR/libidevice_ffi.a"
cp "$SRC/ffi/idevice.h" "$VENDOR/idevice.h"
git -C "$SRC" rev-parse HEAD > "$VENDOR/BUILT_COMMIT"

echo "Installed libidevice_ffi.a + idevice.h into $VENDOR"
