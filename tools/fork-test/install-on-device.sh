#!/bin/sh

#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

# Install the OpenVPN Road Warrior multi-instance test files on a running NethSecurity,
# without rebuilding the image. Copy the files to /tmp/ns-test first, see FORK-TESTING.md.
#
# Usage:
#   sh install-on-device.sh            install the files, keeping a backup of the originals
#   sh install-on-device.sh --restore  put the original files back

set -e

SRC=/tmp/ns-test
BACKUP=/root/ns-test-backup

if [ "$1" = "--restore" ]; then
    if [ ! -d "$BACKUP/files" ]; then
        echo "No backup found in $BACKUP/files" >&2
        exit 1
    fi
    # remove the files that did not exist before the first install
    if [ -f "$BACKUP/new-files" ]; then
        while read -r f; do rm -f "$f"; done < "$BACKUP/new-files"
    fi
    cp -a "$BACKUP/files/." /
    rm -rf "$BACKUP/files" "$BACKUP/new-files"
    /etc/init.d/rpcd restart
    echo "Original files restored."
    echo "The users configuration was not restored, its pre-test copy is $BACKUP/users.config"
    exit 0
fi

mkdir -p "$BACKUP/files"
# keep a copy of this script outside /tmp, so --restore works after a reboot
sed 's/\r$//' "$SRC/install-on-device.sh" > "$BACKUP/install-on-device.sh"

# install_file NAME DEST_DIR MODE
# The first time a file is replaced, the original is saved inside $BACKUP/files.
install_file() {
    dest="$2/$1"
    if [ ! -f "$SRC/$1" ]; then
        echo "Missing $SRC/$1" >&2
        exit 1
    fi
    if grep -qxF "$dest" "$BACKUP/new-files" 2>/dev/null || [ -e "$BACKUP/files$dest" ]; then
        : # original already saved
    elif [ -e "$dest" ]; then
        mkdir -p "$BACKUP/files$2"
        cp -p "$dest" "$BACKUP/files$dest"
    else
        echo "$dest" >> "$BACKUP/new-files"
    fi
    # the files may come from a Windows checkout: drop the CR line endings
    sed 's/\r$//' "$SRC/$1" > "$dest"
    chmod "$3" "$dest"
    echo "Installed $dest"
}

NETHSEC=$(python3 -c 'import os, nethsec; print(os.path.dirname(nethsec.__file__))')

# shared library: a .py file takes precedence over the .pyc shipped by the package
install_file __init__.py "$NETHSEC/ovpn" 644

# APIs
for f in ns.ovpnrw ns.users ns.dashboard; do
    install_file "$f" /usr/libexec/rpcd 755
done

# OpenVPN authentication and connection scripts
for f in openvpn-local-auth openvpn-remote-auth openvpn-otp-auth; do
    install_file "$f" /usr/libexec/ns-openvpn 755
done
for f in 01-check-status 10-static-lease 80-save-connection; do
    install_file "$f" /usr/libexec/ns-openvpn/connect-scripts 755
done

# convert the existing users to per-instance membership, as the first boot of a new image does
if [ ! -e "$BACKUP/users.config" ]; then
    cp -p /etc/config/users "$BACKUP/users.config"
fi
sed 's/\r$//' "$SRC/99_ns-openvpn-user-instances" | sh
echo "Converted the existing Road Warrior users"

# web UI, optional: keep the branding of the device
if [ -d "$SRC/ui" ]; then
    if [ ! -e "$BACKUP/files/www-ns" ]; then
        cp -a /www-ns "$BACKUP/files/www-ns"
    fi
    rm -f "$SRC/ui/branding.js"
    cp -a "$SRC/ui/." /www-ns/
    echo "Installed the web UI"
fi

/etc/init.d/rpcd restart
echo "Done. Reload the web UI with Ctrl+F5. To undo: sh $BACKUP/install-on-device.sh --restore"
