#!/bin/sh

#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

# Show whether the Road Warrior servers use data channel offload (DCO), then their traffic,
# the WAN traffic and the load of each CPU core, until Ctrl+C.
#
# Usage: sh vpn-traffic.sh [SECONDS] [WAN_DEVICE]
#   SECONDS     refresh interval, default 2
#   WAN_DEVICE  default: the device of the default route

INTERVAL=${1:-2}
WAN=${2:-$(ip route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')}

for d in $(ls /sys/class/net | grep '^tunrw'); do
    if grep -q '^DEVTYPE=ovpn$' "/sys/class/net/$d/uevent"; then
        echo "$d: DCO"
    else
        echo "$d: no DCO, the openvpn process handles the traffic"
    fi
done

snapshot() {
    for d in $(ls /sys/class/net | grep '^tunrw') $WAN; do
        [ -d "/sys/class/net/$d" ] || continue
        echo "net $d $(cat "/sys/class/net/$d/statistics/rx_bytes") $(cat "/sys/class/net/$d/statistics/tx_bytes")"
    done
    # total and idle time, then softirq time, where the kernel handles the DCO traffic
    awk '/^cpu[0-9]/ { t = 0; for (i = 2; i <= NF; i++) t += $i; print "cpu", $1, t, $5 + $6, $8 }' /proc/stat
}

echo "Every ${INTERVAL}s, Ctrl+C to stop. Servers: in = from the clients, out = to the clients"
old=$(snapshot)
while sleep "$INTERVAL"; do
    new=$(snapshot)
    printf '%s\n%s\n' "$old" "$new" | awk -v t="$INTERVAL" -v wan="$WAN" '
        { key = $1 " " $2 }
        !(key in a) { a[key] = $3; b[key] = $4; c[key] = $5; next }
        $1 == "net" {
            i = ($3 - a[key]) * 8 / t / 1000000
            o = ($4 - b[key]) * 8 / t / 1000000
            printf "%-18s in %7.1f  out %7.1f Mbit/s\n", ($2 == wan) ? $2 " (WAN)" : $2, i, o
            if ($2 != wan) { ti += i; to += o }
            next
        }
        $1 == "cpu" {
            dt = $3 - a[key]
            if (dt > 0) {
                busy = busy sprintf(" %3d", 100 * (dt - ($4 - b[key])) / dt)
                sirq = sirq sprintf(" %3d", 100 * ($5 - c[key]) / dt)
            }
        }
        END {
            printf "%-18s in %7.1f  out %7.1f Mbit/s\n", "all servers", ti, to
            printf "CPU busy %%:   %s\nCPU softirq %%:%s\n---\n", busy, sirq
        }'
    old=$new
done
