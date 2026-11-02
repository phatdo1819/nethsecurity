#!/usr/bin/python3

#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

# Every minute from cron, see 99-ns-api.wireguard-history: the connections of the peers of the WireGuard servers,
# for the connection-history API of ns.wireguard. See nethsec.wghistory.

import os
import sqlite3
import subprocess
import syslog

from euci import EUci
from nethsec import wgauth, wghistory


def main():
    uci = EUci()
    configured = wghistory.server_peers(uci)
    path = wghistory.db_path(uci)
    # nothing to record, and no connection to close
    if not configured and not os.path.isfile(path):
        return
    try:
        dump = subprocess.run(["wg", "show", "all", "dump"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        # no WireGuard interface: the open connections end
        dump = ""
    # a peer whose enrolled device gave it a WireGuard key of its own keeps its history, see nethsec.wgauth
    keys = wgauth.device_wireguard_keys(wgauth.load_devices())
    peers = {}
    for (interface, public_key), status in wghistory.parse_dump(dump).items():
        peers.setdefault(interface, {})[public_key] = status
    peers = {
        (interface, public_key): status
        for interface, by_key in peers.items()
        for public_key, status in wgauth.to_peer_keys(by_key, keys).items()
    }
    conn = wghistory.connect(path)
    try:
        wghistory.record(conn, peers, configured)
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        main()
    except (sqlite3.Error, OSError) as error:
        syslog.openlog("wireguard-history")
        syslog.syslog(syslog.LOG_ERR, f"can't update the connection history: {error}")
        raise SystemExit(1)
