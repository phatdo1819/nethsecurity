#!/bin/sh

#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

# Runs inside the NethSecurity builder container, started by build-dco.sh: builds OpenVPN with data channel
# offload and the ovpn kernel module for an official release, without building the image.
# Set by build-dco.sh: EXPECTED_KERNEL (<version>~<vermagic> of the official kernel, may be empty)
# and NETHSECURITY_VERSION.
#
# The module must load on the official kernel, so the kernel configuration must not change:
# - kmod-ovpn-backports normally enables AF_KCM to get the stream parser (used by TCP connections),
#   which the official kernel doesn't have: the option is dropped and the module gets its own copy
#   of the stream parser, built from the kernel sources
# - the vermagic of the kernel built here must be the one of the official kernel package

set -e

cd /home/buildbot/openwrt

mk() {
    # on error, run again on one job with the full output, to show the cause
    make -j"$(nproc)" "$@" || make -j1 V=s "$@"
}

KMOD_MAKEFILE=feeds/packages/kernel/ovpn-dco/Makefile
sed -i '/KCONFIG:=CONFIG_AF_KCM/d' "$KMOD_MAKEFILE"
if grep -q 'KCONFIG:=CONFIG_AF_KCM' "$KMOD_MAKEFILE"; then
    echo "Can't drop AF_KCM from $KMOD_MAKEFILE" >&2
    exit 1
fi
make defconfig
for opt in CONFIG_OPENVPN_openssl_ENABLE_DCO CONFIG_PACKAGE_kmod-ovpn-backports; do
    if ! grep -q "^$opt=y" .config; then
        echo "$opt is not enabled" >&2
        exit 1
    fi
done

echo "=== Building the tools, the toolchain and the kernel"
mk tools/install
mk toolchain/install
mk target/linux/compile

LINUX_DIR=$(ls -d build_dir/target-*/linux-*/linux-[0-9]* | head -n 1)
KERNEL_VERSION=${LINUX_DIR##*/linux-}
VERMAGIC=$(cat "$LINUX_DIR/.vermagic")
echo "=== Kernel $KERNEL_VERSION~$VERMAGIC"
if [ -z "$EXPECTED_KERNEL" ]; then
    echo "WARNING: the official kernel is unknown, can't check that the module matches it" >&2
elif [ "$KERNEL_VERSION~$VERMAGIC" != "$EXPECTED_KERNEL" ]; then
    echo "The kernel built here ($KERNEL_VERSION~$VERMAGIC) is not the official one ($EXPECTED_KERNEL):" >&2
    echo "the module would not load on the firewall" >&2
    exit 1
fi

echo "=== Building the ovpn kernel module"
mk package/feeds/packages/ovpn-dco/prepare
OVPN_DIR=$(ls -d build_dir/target-*/linux-*/ovpn-backports-*/drivers/net/ovpn | head -n 1)
if ! grep -q ovpn_strp_init "$OVPN_DIR/main.c"; then
    cp "$LINUX_DIR/net/strparser/strparser.c" "$OVPN_DIR/strparser.c"
    # the stream parser becomes part of the module: no exports, its workqueue is created by the module
    perl -0pi -e '
        s/^EXPORT_SYMBOL_GPL\(\w+\);\n//mg;
        s/^(#include <net\/sock.h>\n)/$1\nint ovpn_strp_init(void);\nvoid ovpn_strp_exit(void);\n/m
            or die "strparser.c: includes not found\n";
        s/^static int __init strp_dev_init\(void\)$/int ovpn_strp_init(void)/m
            or die "strparser.c: strp_dev_init not found\n";
        s/^device_initcall\(strp_dev_init\);$/void ovpn_strp_exit(void)\n{\n\tdestroy_workqueue(strp_wq);\n}/m
            or die "strparser.c: device_initcall not found\n";
    ' "$OVPN_DIR/strparser.c"
    perl -0pi -e '
        s/^module_init\(ovpn_init\);\nmodule_exit\(ovpn_cleanup\);\n/int ovpn_strp_init(void);
void ovpn_strp_exit(void);

static int __init ovpn_init_with_strp(void)
{
	int err = ovpn_strp_init();

	if (err)
		return err;
	err = ovpn_init();
	if (err)
		ovpn_strp_exit();
	return err;
}

static void __exit ovpn_cleanup_with_strp(void)
{
	ovpn_cleanup();
	ovpn_strp_exit();
}

module_init(ovpn_init_with_strp);
module_exit(ovpn_cleanup_with_strp);
/m or die "main.c: module_init not found\n";
    ' "$OVPN_DIR/main.c"
    echo 'ovpn-y += strparser.o' >> "$OVPN_DIR/Makefile"
fi
mk package/feeds/packages/ovpn-dco/compile

echo "=== Building OpenVPN"
mk package/feeds/packages/openvpn/compile

echo "=== Collecting the files"
OUT=bin/dco
rm -rf "$OUT"
mkdir -p "$OUT/pkg/root/usr/sbin" "$OUT/pkg/root/usr/lib"
idir() {
    d=$(find build_dir -type d -path "*/ipkg-*/$1" | head -n 1)
    if [ -z "$d" ]; then
        echo "Package $1 not found in build_dir" >&2
        exit 1
    fi
    echo "$d"
}
cp -a "$(idir kmod-ovpn-backports)/." "$OUT/pkg/root/"
# only the program: the configuration and the init script of the official package stay
cp -a "$(idir openvpn-openssl)/usr/sbin/openvpn" "$OUT/pkg/root/usr/sbin/"
for lib in libnl-core libnl-genl; do
    cp -a "$(idir "$lib")/usr/lib/." "$OUT/pkg/root/usr/lib/"
done
OPENVPN_VERSION=$(grep -m 1 '^PKG_VERSION:=' feeds/packages/net/openvpn/Makefile | cut -d= -f2)
cat > "$OUT/pkg/BUILD-INFO" <<EOF
DCO_NETHSECURITY_VERSION=$NETHSECURITY_VERSION
DCO_KERNEL=$KERNEL_VERSION
DCO_KERNEL_VERMAGIC=$VERMAGIC
DCO_OPENVPN_VERSION=$OPENVPN_VERSION
EOF
tar -czf "$OUT/ns-dco.tar.gz" -C "$OUT/pkg" BUILD-INFO root
(cd "$OUT/pkg" && find root ! -type d | sort)

# the build directories are kept for the next builds: remove the modified module sources,
# so a full image build starts from the original ones
make package/feeds/packages/ovpn-dco/clean
echo "=== Done: $OUT/ns-dco.tar.gz"
