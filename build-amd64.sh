#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Build amd64/wireguard.exe from Git Bash on a Windows box.
#
# This mirrors what the upstream build.bat does, but downloads only the pieces
# that are needed for amd64 and skips wg.exe:
#
#   Go            compiles the program
#   llvm-mingw    provides the x86_64-w64-mingw32-windres resource compiler
#   ImageMagick   converts ui/icon/*.svg into the .ico files resources.rc wants
#   WireGuardNT   provides wireguard.dll and wireguard.sys, embedded into the
#                 executable as RCDATA resources
#
# The resources matter: the manifest is what gets the GUI the version 6 common
# controls and per-monitor DPI, and ui/iconprovider.go loads the tray icon from
# resource id 7, so a resource-less build produces a tray icon that never shows
# up. With -tags load_wgnt_from_rsrc, driver/dll_fromrsrc_windows.go loads
# wireguard.dll from those same resources, so no DLL has to sit next to the
# executable.
#
# The WireGuardNT driver must already be installed on the machine; this script
# does not install a driver.
#
# Deliberately no -overlay. The .overlay/ tree in this fork replaces
# crypto/internal/fips140deps/cpu/cpu.go with a shim that re-exports only
# HasSHA512AVX2/HasSHA512ARM64, while crypto/internal/fips140/{aes,bigmod,
# sha256,sha3} need the full set of cpu.X86Has*/ARM64 re-exports, so against the
# pinned Go 1.27.1 it fails with a wall of "undefined: cpu.X86HasADX".
#
# Usage:  ./build-amd64.sh [--clean] [--deps-only] [--no-resources] [--overlay]
#   --clean         throw away .deps first, forcing a fresh toolchain download
#   --deps-only     only fetch the toolchain and pre-populate the module cache
#   --no-resources  build without the resource section, and stage
#                   wireguard.dll next to the executable instead. Fast, but the
#                   GUI loses its manifest and its tray icon
#   --overlay       also pass -overlay .overlay/overlay.json, as upstream does;
#                   known to fail against Go 1.27.1, kept for comparison
set -euo pipefail

DEPS_ONLY=
CLEAN=
NO_RESOURCES=
USE_OVERLAY=
for arg in "$@"; do
	case "$arg" in
		--clean) CLEAN=1 ;;
		--deps-only) DEPS_ONLY=1 ;;
		--no-resources) NO_RESOURCES=1 ;;
		--overlay) USE_OVERLAY=1 ;;
		*) echo "error: unknown argument $arg" >&2; exit 1 ;;
	esac
done

cd "$(dirname "$0")"
ROOT="$PWD"
DEPS="$ROOT/.deps"

if [ -n "$CLEAN" ]; then
	case "$DEPS" in
		"$ROOT"/.deps) rm -rf "$DEPS" ;;
		*) echo "error: refusing to clean $DEPS" >&2; exit 1 ;;
	esac
fi

GO_URL="https://go.dev/dl/go1.27.1.windows-amd64.zip"
GO_URL_MIRROR="https://golang.google.cn/dl/go1.27.1.windows-amd64.zip"
GO_SHA="a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d"

MINGW_URL="https://download.wireguard.com/windows-toolchain/distfiles/llvm-mingw-20260311-ucrt-x86_64.zip"
MINGW_SHA="dd4c67d98959479c7be2fb6709ba074475991590848cb9d0eb2620be06b182e1"

IMAGEMAGICK_URL="https://download.wireguard.com/windows-toolchain/distfiles/ImageMagick-7.0.8-42-portable-Q16-x64.zip"
IMAGEMAGICK_SHA="584e069f56456ce7dde40220948ff9568ac810688c892c5dfb7f6db902aa05aa"

WGNT_URL="https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip"
WGNT_SHA="dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace"

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
	echo "error: no python interpreter found (needed to unpack the toolchain zips)" >&2
	return 1
}

PY="$(find_python)"

# unpack_zip <zip> <destdir> <strip_components>
unpack_zip() {
	"$PY" - "$1" "$2" "$3" <<-'PYEOF'
		import os, shutil, sys, zipfile
		src, dst, strip = sys.argv[1], sys.argv[2], int(sys.argv[3])
		with zipfile.ZipFile(src) as archive:
		    for info in archive.infolist():
		        parts = info.filename.split('/')
		        if len(parts) <= strip:
		            continue
		        rel = '/'.join(parts[strip:])
		        if not rel:
		            continue
		        target = os.path.join(dst, rel)
		        if info.is_dir():
		            os.makedirs(target, exist_ok=True)
		            continue
		        os.makedirs(os.path.dirname(target), exist_ok=True)
		        with archive.open(info) as srcf, open(target, 'wb') as dstf:
		            shutil.copyfileobj(srcf, dstf)
	PYEOF
}

# fetch <url> <mirror> <sha256> <destfile>
fetch() {
	local url="$1" mirror="$2" sha="$3" dest="$4"
	if [ -f "$dest" ] && echo "$sha  $dest" | sha256sum -c --status 2>/dev/null; then
		echo "[+] cached $dest"
		return 0
	fi
	for source in "$url" "$mirror"; do
		[ -n "$source" ] || continue
		echo "[+] downloading $source"
		if curl -fL --retry 3 --connect-timeout 20 --progress-bar -o "$dest.tmp" "$source"; then
			if echo "$sha  $dest.tmp" | sha256sum -c --status 2>/dev/null; then
				mv "$dest.tmp" "$dest"
				echo "[+] verified $dest"
				return 0
			fi
			echo "[-] sha256 mismatch for $source, trying next source" >&2
			rm -f "$dest.tmp"
		else
			echo "[-] download failed for $source, trying next source" >&2
			rm -f "$dest.tmp"
		fi
	done
	echo "[-] unable to obtain $dest" >&2
	return 1
}

mkdir -p "$DEPS"

if [ ! -x "$DEPS/go/bin/go.exe" ]; then
	fetch "$GO_URL" "$GO_URL_MIRROR" "$GO_SHA" "$DEPS/go.zip"
	echo "[+] unpacking Go"
	unpack_zip "$DEPS/go.zip" "$DEPS" 0
fi

if [ ! -f "$DEPS/wireguard-nt/bin/amd64/wireguard.dll" ]; then
	fetch "$WGNT_URL" "" "$WGNT_SHA" "$DEPS/wireguard-nt.zip"
	echo "[+] unpacking WireGuardNT"
	unpack_zip "$DEPS/wireguard-nt.zip" "$DEPS" 0
fi

if [ -z "$NO_RESOURCES" ]; then
	if [ ! -d "$DEPS/llvm-mingw" ]; then
		fetch "$MINGW_URL" "" "$MINGW_SHA" "$DEPS/llvm-mingw.zip"
		echo "[+] unpacking llvm-mingw"
		unpack_zip "$DEPS/llvm-mingw.zip" "$DEPS/llvm-mingw" 1
	fi
	if [ ! -d "$DEPS/imagemagick" ]; then
		fetch "$IMAGEMAGICK_URL" "" "$IMAGEMAGICK_SHA" "$DEPS/imagemagick.zip"
		echo "[+] unpacking ImageMagick"
		unpack_zip "$DEPS/imagemagick.zip" "$DEPS/imagemagick" 0
	fi
fi

GOEXE="$DEPS/go/bin/go.exe"
export GOOS=windows
export GOARCH=amd64
export GOARM=7
export CGO_ENABLED=0
export GOPATH="$ROOT\\.deps\\gopath"
export GOCACHE="$ROOT\\.deps\\gocache"

VERSION="$(sed -n 's/^\s*Number\s*=\s*"\([0-9.]\+\)"$/\1/p' version/version.go)"
echo "[+] version $VERSION"

if [ -n "$DEPS_ONLY" ]; then
	echo "[+] pre-populating the module cache"
	"$GOEXE" mod download
	echo "[+] done (deps only)"
	exit 0
fi

TAGS=()
if [ -z "$NO_RESOURCES" ]; then
	echo "[+] rendering icons from ui/icon/*.svg"
	for svg in ui/icon/*.svg; do
		ico="${svg%.svg}.ico"
		"$DEPS/imagemagick/convert.exe" -background none "$(cygpath -w "$PWD/$svg")" \
			-define icon:auto-resize="256,192,128,96,64,48,40,32,24,20,16" -compress zip \
			"$(cygpath -w "$PWD/$ico")"
	done

	WINDRES="$DEPS/llvm-mingw/bin/x86_64-w64-mingw32-windres.exe"
	if [ ! -x "$WINDRES" ]; then
		echo "error: $WINDRES not found, cannot assemble the resource section" >&2
		exit 1
	fi
	VERSION_ARRAY="$(echo "$VERSION" | awk -F. '{printf "%s,%s,%s,%s", $1?$1:0, $2?$2:0, $3?$3:0, $4?$4:0}')"
	echo "[+] assembling resources (version $VERSION_ARRAY)"
	"$WINDRES" -I ".deps/wireguard-nt/bin/amd64" \
		-DWIREGUARD_VERSION_ARRAY="$VERSION_ARRAY" -DWIREGUARD_VERSION_STR="$VERSION" \
		-i resources.rc -o resources_amd64.syso -O coff -c 65001
	TAGS=(-tags load_wgnt_from_rsrc)
else
	echo "[+] building without resources; wireguard.dll will be staged next to the executable"
fi

mkdir -p amd64
BUILD_FLAGS=(-ldflags="-H windowsgui -s -w" -trimpath -buildvcs=false -o amd64/wireguard.exe .)
if [ -n "$USE_OVERLAY" ]; then
	echo "[+] using -overlay .overlay/overlay.json (known to fail against Go 1.27.1)"
	BUILD_FLAGS=(-overlay .overlay/overlay.json "${BUILD_FLAGS[@]}")
fi
echo "[+] building amd64/wireguard.exe"
"$GOEXE" build "${TAGS[@]}" "${BUILD_FLAGS[@]}"

rm -f amd64/wireguard.dll
if [ -n "$NO_RESOURCES" ]; then
	echo "[+] staging wireguard.dll next to the executable"
	cp -f "$DEPS/wireguard-nt/bin/amd64/wireguard.dll" amd64/wireguard.dll
fi

echo "[+] done:"
ls -l amd64/
