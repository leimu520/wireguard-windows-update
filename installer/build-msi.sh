#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Builds the amd64 MSI installer.
#
# Differences from installer/build.bat, which this replaces:
#
#   * amd64 only, like the rest of this repository;
#   * the WiX zip is unpacked with Python, because in a Git Bash environment GNU
#     tar shadows the bsdtar in System32 and cannot read the archive;
#   * nothing is signed, since there is no certificate here.
#
# Prerequisites: run ./build-amd64.sh first, so that amd64/wireguard.exe,
# amd64/wg.exe and ui/icon/wireguard.ico exist.
#
# Usage:  ./installer/build-msi.sh

set -euo pipefail

cd "$(dirname "$0")"
INSTALLER_DIR="$PWD"
ROOT="$(cd .. && pwd)"
DEPS="$ROOT/.deps"

WIX_URL="https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip"
WIX_SHA="6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31"
WIX_DIR="$INSTALLER_DIR/.deps/wix"

PLATFORM=amd64
WIX_ARCH=x64

find_python() {
	for candidate in python3 python; do
		if command -v "$candidate" > /dev/null 2>&1; then
			command -v "$candidate"
			return 0
		fi
	done
	for candidate in \
		"/c/Users/$USER/.workbuddy/binaries/python/versions"/*/python.exe \
		"/c/Program Files/Python3"*/python.exe; do
		if [ -x "$candidate" ]; then
			echo "$candidate"
			return 0
		fi
	done
	echo "error: no python interpreter found (needed to unpack the WiX zip)" >&2
	return 1
}

PY="$(find_python)"

VERSION="$(sed -n 's/^[[:space:]]*Number[[:space:]]*=[[:space:]]*"\([0-9.]\+\)".*/\1/p' "$ROOT/version/version.go")"
if [ -z "$VERSION" ]; then
	echo "error: could not read the version out of version/version.go" >&2
	exit 1
fi
echo "[+] version $VERSION"

for required in "$ROOT/$PLATFORM/wireguard.exe" "$ROOT/$PLATFORM/wg.exe" "$ROOT/ui/icon/wireguard.ico"; do
	if [ ! -f "$required" ]; then
		echo "error: $required is missing; run ./build-amd64.sh first" >&2
		exit 1
	fi
done

if [ ! -d "$WIX_DIR" ]; then
	echo "[+] fetching the WiX toolset"
	mkdir -p "$INSTALLER_DIR/.deps"
	curl -sS -L -o "$INSTALLER_DIR/.deps/wix-binaries.zip" "$WIX_URL"
	echo "$WIX_SHA  $INSTALLER_DIR/.deps/wix-binaries.zip" | sha256sum -c - || {
		echo "error: the WiX download does not match its checksum" >&2
		exit 1
	}
	mkdir -p "$WIX_DIR/bin"
	"$PY" - "$INSTALLER_DIR/.deps/wix-binaries.zip" "$WIX_DIR/bin" <<'PYEOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    z.extractall(sys.argv[2])
PYEOF
	rm -f "$INSTALLER_DIR/.deps/wix-binaries.zip"
fi

CANDLE="$WIX_DIR/bin/candle.exe"
LIGHT="$WIX_DIR/bin/light.exe"
if [ ! -x "$CANDLE" ] || [ ! -x "$LIGHT" ]; then
	echo "error: candle.exe / light.exe are not where they were expected in $WIX_DIR" >&2
	exit 1
fi

CC="$DEPS/llvm-mingw/bin/x86_64-w64-mingw32-gcc.exe"
if [ ! -x "$CC" ]; then
	echo "error: $CC is missing; run ./build-amd64.sh --deps-only first" >&2
	exit 1
fi

CFLAGS="-O3 -Wall -std=gnu11 -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00 -municode -DUNICODE -D_UNICODE -DNDEBUG"
LDFLAGS="-shared -s -Wl,--kill-at -Wl,--major-os-version=10 -Wl,--minor-os-version=0 -Wl,--major-subsystem-version=10 -Wl,--minor-subsystem-version=0 -Wl,--tsaware -Wl,--dynamicbase -Wl,--nxcompat -Wl,--export-all-symbols"
LDLIBS="-lmsi -lole32 -lshlwapi -lshell32 -luuid -lntdll"

mkdir -p "$PLATFORM" dist

echo "[+] compiling customactions.dll"
# shellcheck disable=SC2086
"$CC" $CFLAGS $LDFLAGS -o "$PLATFORM/customactions.dll" customactions.c $LDLIBS

echo "[+] running candle"
"$CANDLE" -nologo \
	-dWIREGUARD_VERSION="$VERSION" \
	-dWIREGUARD_PLATFORM="$PLATFORM" \
	-out "$PLATFORM/wireguard.wixobj" \
	-arch "$WIX_ARCH" \
	wireguard.wxs

MSI="dist/wireguard-$PLATFORM-$VERSION.msi"
echo "[+] running light"
"$LIGHT" -nologo -spdb -sice:ICE39 -sice:ICE61 -sice:ICE03 -out "$MSI" "$PLATFORM/wireguard.wixobj"

echo "[+] done: $INSTALLER_DIR/$MSI"
ls -l "$MSI"
