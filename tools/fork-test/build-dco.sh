#!/bin/bash

#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

# Build OpenVPN with data channel offload (DCO) and the ovpn kernel module for an official
# NethSecurity release, to install them with install-on-device.sh. See FORK-TESTING.md.
# Runs on a x86_64 Linux machine with podman, git, curl and python3.
#
# Usage: tools/fork-test/build-dco.sh [VERSION]    (default: 8.8.0)
# Result: ns-dco-<VERSION>.tar.gz in the current directory

set -euo pipefail

VERSION=${1:-8.8.0}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
# the release sources are copied here, outside the clone
WORK=${WORK:-${XDG_CACHE_HOME:-$HOME/.cache}/ns-dco-build}
RESULT=$PWD/ns-dco-$VERSION.tar.gz

if [ "$(uname -m)" != "x86_64" ]; then
    echo "The NethSecurity builder needs a x86_64 machine" >&2
    exit 1
fi

# the kernel of the official release: the module is checked against it
INDEX=https://updates.nethsecurity.nethserver.org/stable/$VERSION/targets/x86/64/packages/packages.adb
EXPECTED_KERNEL=$(curl -sSfL "$INDEX" | python3 -c '
import re, sys, zlib
data = sys.stdin.buffer.read()
if data[:4] == b"ADBd":
    data = zlib.decompress(data[4:], -15)
m = re.search(rb"kernel.(\d+\.\d+\.\d+)~([0-9a-f]{32})-r\d+", data)
print(f"{m.group(1).decode()}~{m.group(2).decode()}" if m else "")
' || true)
echo "Official kernel of $VERSION: ${EXPECTED_KERNEL:-unknown}"

# a clean copy of the release sources, with DCO enabled
git -C "$REPO" fetch --quiet https://github.com/NethServer/nethsecurity.git "refs/tags/$VERSION:refs/tags/$VERSION"
rm -rf "$WORK"
mkdir -p "$WORK"
git -C "$REPO" archive "$VERSION" | tar -x -C "$WORK"
printf '%s\n' 'CONFIG_OPENVPN_openssl_ENABLE_DCO=y' >> "$WORK/config/openvpn.conf"

cd "$WORK"
./build-nethsec.sh sh -c "EXPECTED_KERNEL='$EXPECTED_KERNEL' NETHSECURITY_VERSION='$VERSION'; export EXPECTED_KERNEL NETHSECURITY_VERSION; $(cat "$HERE/dco-build-in-container.sh")"
cp bin/dco/ns-dco.tar.gz "$RESULT"
echo "Built $RESULT"
