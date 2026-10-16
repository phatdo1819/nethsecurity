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

# put_file SOURCE DEST
# Copy through a temporary name and rename it: a running program, like openvpn, can't be overwritten.
put_file() {
    mkdir -p "$(dirname "$2")"
    cp -a "$1" "$2.ns-test-new"
    mv -f "$2.ns-test-new" "$2"
}

if [ "$1" = "--restore" ]; then
    if [ ! -d "$BACKUP/files" ]; then
        echo "No backup found in $BACKUP/files" >&2
        exit 1
    fi
    dco_loaded=""
    if grep -q '^ovpn ' /proc/modules; then
        dco_loaded=1
    fi
    # remove the files that did not exist before the first install
    if [ -f "$BACKUP/new-files" ]; then
        while read -r f; do rm -f "$f"; done < "$BACKUP/new-files"
    fi
    (cd "$BACKUP/files" && find . ! -type d) | while read -r f; do
        put_file "$BACKUP/files${f#.}" "${f#.}"
    done
    rm -rf "$BACKUP/files" "$BACKUP/new-files"
    /etc/init.d/rpcd restart
    if [ -n "$dco_loaded" ]; then
        # the original OpenVPN doesn't use the DCO kernel module
        /etc/init.d/openvpn restart
        rmmod ovpn 2>/dev/null || echo "The DCO kernel module is still loaded, it goes away at the next reboot"
    fi
    echo "Original files restored."
    echo "The users configuration was not restored, its pre-test copy is $BACKUP/users.config"
    exit 0
fi

mkdir -p "$BACKUP/files"
# keep a copy of this script outside /tmp, so --restore works after a reboot
sed 's/\r$//' "$SRC/install-on-device.sh" > "$BACKUP/install-on-device.sh"

# save_original DEST
# The first time a file is replaced, the original is saved inside $BACKUP/files.
save_original() {
    if grep -qxF "$1" "$BACKUP/new-files" 2>/dev/null || [ -e "$BACKUP/files$1" ] || [ -L "$BACKUP/files$1" ]; then
        : # original already saved
    elif [ -e "$1" ] || [ -L "$1" ]; then
        mkdir -p "$BACKUP/files$(dirname "$1")"
        cp -a "$1" "$BACKUP/files$1"
    else
        echo "$1" >> "$BACKUP/new-files"
    fi
}

# install_file NAME DEST_DIR MODE
install_file() {
    dest="$2/$1"
    if [ ! -f "$SRC/$1" ]; then
        echo "Missing $SRC/$1" >&2
        exit 1
    fi
    save_original "$dest"
    # the files may come from a Windows checkout: drop the CR line endings
    sed 's/\r$//' "$SRC/$1" > "$dest.ns-test-new"
    chmod "$3" "$dest.ns-test-new"
    mv -f "$dest.ns-test-new" "$dest"
    echo "Installed $dest"
}

# install_dco: OpenVPN with data channel offload and the ovpn kernel module, from ns-dco.tar.gz
install_dco() {
    dco="$SRC/dco"
    rm -rf "$dco"
    mkdir -p "$dco"
    tar -xzf "$SRC/ns-dco.tar.gz" -C "$dco"
    . "$dco/BUILD-INFO"
    if [ "$(uname -r)" != "$DCO_KERNEL" ]; then
        echo "Skipped DCO: the files are for kernel $DCO_KERNEL, this firewall runs $(uname -r)" >&2
        return 0
    fi
    # check that the new program starts with the libraries of the firewall plus the ones in the archive
    if ! LD_LIBRARY_PATH="$dco/root/usr/lib" "$dco/root/usr/sbin/openvpn" --version 2>&1 | grep -q '\[DCO\]'; then
        echo "Skipped DCO: the new openvpn program doesn't start on this firewall:" >&2
        LD_LIBRARY_PATH="$dco/root/usr/lib" "$dco/root/usr/sbin/openvpn" --version 2>&1 | head -n 3 >&2 || true
        return 0
    fi

    /etc/init.d/openvpn stop
    # an older DCO module may be loaded: unload it, so the new one is used
    rmmod ovpn 2>/dev/null || true
    (cd "$dco/root" && find . ! -type d) | while read -r f; do
        save_original "${f#.}"
        put_file "$dco/root${f#.}" "${f#.}"
        echo "Installed ${f#.}"
    done
    if modprobe ovpn 2>/dev/null && grep -q '^ovpn ' /proc/modules; then
        echo "Loaded the DCO kernel module (ovpn)"
    else
        echo "The DCO kernel module didn't load, OpenVPN works without it. Kernel messages:" >&2
        dmesg | tail -n 5 >&2
    fi
    /etc/init.d/openvpn start
    echo "Restarted OpenVPN: the clients reconnect"
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
# firewall rules for client-to-client, needed with DCO
if [ -f "$SRC/99_ns-openvpn-client-to-client" ]; then
    sed 's/\r$//' "$SRC/99_ns-openvpn-client-to-client" | sh
    /etc/init.d/firewall reload >/dev/null 2>&1 || true
    echo "Checked the client-to-client firewall rules"
fi

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

# OpenVPN data channel offload (DCO), optional
if [ -f "$SRC/ns-dco.tar.gz" ]; then
    install_dco
fi

echo "Done. Reload the web UI with Ctrl+F5. To undo: sh $BACKUP/install-on-device.sh --restore"
