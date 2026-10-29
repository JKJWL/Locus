#!/usr/bin/env bash
# Builds the userspace WireGuard proxy (Vendor/wgproxy-src, Go) as an iOS
# arm64 static library at Vendor/wgproxy/libwgproxy.a. Requires macOS with
# Xcode + Go 1.23+.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/Vendor/wgproxy-src"
OUT="$ROOT/Vendor/wgproxy"

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
FLAGS="-isysroot $SDK -arch arm64 -miphoneos-version-min=18.0"

cd "$SRC"
go mod tidy
CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
CC="$(xcrun --sdk iphoneos -f clang)" \
CGO_CFLAGS="$FLAGS" CGO_LDFLAGS="$FLAGS" \
  go build -buildmode=c-archive -trimpath -ldflags="-s -w" -o "$OUT/libwgproxy.a" .

# cgo also emits a generated header; Swift uses the hand-written wgproxy.h.
rm -f "$OUT/libwgproxy.h"
echo "Installed $OUT/libwgproxy.a"
