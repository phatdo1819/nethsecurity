#!/usr/bin/python3

#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
The connection history of the WireGuard servers.

WireGuard has no connections: a peer is there while its handshakes keep coming, at least every 2 minutes while it
sends anything, its keepalive too. `record` runs every minute on the output of `wg show all dump` and keeps a row for
each connection: it starts with a recent handshake of a peer, follows its byte counters, and ends when the latest
handshake is older than `ACTIVE_WINDOW`, when the peer comes from another address, or when its counters start again
from zero because the interface restarted.

The rows are in `connections.db`, on the data storage when there is one, like the history of OpenVPN, else in /var,
lost at reboot. See docs/design/wireguard_connection_history.md.
"""

import csv
import ipaddress
import os
import pathlib
import sqlite3
import time
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from nethsec import utils

# REJECT_AFTER_TIME of WireGuard: without a newer handshake, no data can pass
ACTIVE_WINDOW = 180
# an open row not updated for this long: the recorder didn't run, the connection is over
STALE_AFTER = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    instance TEXT NOT NULL,
    peer TEXT NOT NULL,
    peer_name TEXT,
    user TEXT,
    public_key TEXT NOT NULL,
    virtual_ip_addr TEXT,
    remote_ip_addr TEXT,
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    last_seen INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    rx_start INTEGER NOT NULL DEFAULT 0,
    tx_start INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_connections_start ON connections (start_time);
CREATE INDEX IF NOT EXISTS idx_connections_open ON connections (end_time);
CREATE TABLE IF NOT EXISTS counters (
    instance TEXT NOT NULL,
    public_key TEXT NOT NULL,
    rx INTEGER NOT NULL,
    tx INTEGER NOT NULL,
    PRIMARY KEY (instance, public_key)
);
"""

# the end of a row for the queries, NULL while connected: an open row not updated for STALE_AFTER ended when it
# was last seen
END = "COALESCE(end_time, CASE WHEN :now - last_seen > :stale THEN last_seen END)"
COLUMNS = (
    f"instance, peer, peer_name, user, virtual_ip_addr, remote_ip_addr, start_time, {END} AS ended, "
    "bytes_received, bytes_sent"
)
SORT_COLUMNS = {
    "account": "peer_name",
    "user": "user",
    "instance": "instance",
    "startTime": "start_time",
    "endTime": f"COALESCE({END}, :now)",
    "duration": f"COALESCE({END}, :now) - start_time",
    "bytesReceived": "bytes_received",
    "bytesSent": "bytes_sent",
}
# sorted in Python: SQLite compares them as text
SORT_ADDRESSES = {"virtualIpAddress": 4, "remoteIpAddress": 5}


def db_path(uci):
    """
    Return the path of the connection history.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - `<data storage>/wireguard/connections.db`, or `/var/wireguard/connections.db` without a data storage
    """
    base = uci.get("fstab", "ns_data", "target", default="")
    if not base or not os.path.isdir(base):
        base = "/var"
    return os.path.join(base, "wireguard", "connections.db")


def connect(path):
    """
    Open the connection history to write it, creating it if missing.

    Arguments:
      - path -- the database, see `db_path`

    Returns:
      - a sqlite3 connection
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.executescript(SCHEMA)
    return conn


def open_readonly(path):
    """
    Open the connection history to read it.

    Arguments:
      - path -- the database, see `db_path`

    Returns:
      - a sqlite3 connection, None if there is no history yet
    """
    if not os.path.isfile(path):
        return None
    return sqlite3.connect(pathlib.Path(path).as_uri() + "?mode=ro", uri=True, timeout=10)


def remote_address(endpoint):
    """
    Return the IP of a WireGuard endpoint.

    Arguments:
      - endpoint -- `1.2.3.4:51820`, `[2001:db8::1]:51820` or `(none)`

    Returns:
      - the IP without the port, empty if there is no endpoint
    """
    if not endpoint or endpoint == "(none)":
        return ""
    if endpoint.startswith("["):
        return endpoint[1 : endpoint.find("]")]
    return endpoint.rsplit(":", 1)[0]


def parse_dump(text):
    """
    Parse the output of `wg show all dump`.

    Arguments:
      - text -- the output: a line for each interface, then a line for each of its peers

    Returns:
      - a dictionary `{(interface, public_key): {"remote", "handshake", "rx", "tx"}}` of the peers
    """
    peers = {}
    for line in text.splitlines():
        fields = line.split("\t")
        # the lines of the interfaces have 5 fields
        if len(fields) != 9 or not fields[5].isdigit() or not fields[6].isdigit() or not fields[7].isdigit():
            continue
        interface, public_key, _psk, endpoint, _allowed, handshake, rx, tx, _keepalive = fields
        peers[(interface, public_key)] = {
            "remote": remote_address(endpoint),
            "handshake": int(handshake),
            "rx": int(rx),
            "tx": int(tx),
        }
    return peers


def server_peers(uci):
    """
    List the peers of the WireGuard servers: the client tunnels have no history.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - a dictionary `{(server, public_key): {"peer", "name", "user", "address"}}`
    """
    peers = {}
    for server, options in (utils.get_all_by_type(uci, "network", "interface") or {}).items():
        if options.get("proto") != "wireguard" or options.get("ns_type") != "server":
            continue
        for section, peer in (utils.get_all_by_type(uci, "network", f"wireguard_{server}") or {}).items():
            if peer.get("public_key"):
                peers[(server, peer["public_key"])] = {
                    "peer": section,
                    "name": peer.get("ns_name", ""),
                    "user": peer.get("ns_user", ""),
                    "address": peer.get("ns_ip", ""),
                }
    return peers


def record(conn, peers, configured, now=None):
    """
    Update the connection history with the state of the peers.

    Arguments:
      - conn -- the history, see `connect`
      - peers -- the peers as WireGuard has them, see `parse_dump`
      - configured -- the peers of the servers, see `server_peers`: the others are ignored
      - now -- the current time, seconds since 1970
    """
    now = int(time.time() if now is None else now)
    counters = {(row[0], row[1]): (row[2], row[3]) for row in conn.execute("SELECT * FROM counters")}
    open_rows = {}
    for rowid, instance, public_key, remote, last_seen, rx_start, tx_start, start in conn.execute(
        "SELECT rowid, instance, public_key, remote_ip_addr, last_seen, rx_start, tx_start, start_time "
        "FROM connections WHERE end_time IS NULL"
    ):
        open_rows[(instance, public_key)] = {
            "rowid": rowid,
            "remote": remote,
            "last_seen": last_seen,
            "rx_start": rx_start,
            "tx_start": tx_start,
            "start": start,
        }

    def close(row):
        conn.execute("UPDATE connections SET end_time = ? WHERE rowid = ?", (row["last_seen"], row["rowid"]))

    # gone from WireGuard, the interface is down, or from the configuration
    for key, row in open_rows.items():
        if key not in peers or key not in configured:
            close(row)

    for key, status in peers.items():
        if key not in configured:
            continue
        info = configured[key]
        rx, tx = status["rx"], status["tx"]
        active = status["handshake"] > 0 and now - status["handshake"] <= ACTIVE_WINDOW
        row = open_rows.get(key)
        start = status["handshake"]
        previous = counters.get(key)
        if row is not None:
            # lower than a minute ago: the interface restarted
            reset = previous is not None and (rx < previous[0] or tx < previous[1])
            moved = active and status["remote"] != "" and row["remote"] != "" and status["remote"] != row["remote"]
            stale = now - row["last_seen"] > STALE_AFTER
            if reset or stale or moved or not active:
                # the bytes of the last minute of a reset are lost: the counters restarted
                close(row)
                start = max(row["last_seen"], start if not moved else now)
                row = None
            else:
                changed = previous != (rx, tx)
                conn.execute(
                    "UPDATE connections SET bytes_received = ?, bytes_sent = ?, last_seen = ?, peer_name = ?, "
                    "user = ?, virtual_ip_addr = ?, remote_ip_addr = ? WHERE rowid = ?",
                    (
                        rx - row["rx_start"],
                        tx - row["tx_start"],
                        now if changed else row["last_seen"],
                        info["name"],
                        info["user"],
                        info["address"],
                        status["remote"] or row["remote"],
                        row["rowid"],
                    ),
                )
        if row is None and active:
            # the counters since the last minute are of this connection: before, it wasn't there
            if previous is not None and previous[0] <= rx and previous[1] <= tx:
                rx_start, tx_start = previous
            else:
                # first seen, or the counters restarted
                rx_start, tx_start = 0, 0
            conn.execute(
                "INSERT INTO connections (instance, peer, peer_name, user, public_key, virtual_ip_addr, "
                "remote_ip_addr, start_time, last_seen, bytes_received, bytes_sent, rx_start, tx_start) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    key[0],
                    info["peer"],
                    info["name"],
                    info["user"],
                    key[1],
                    info["address"],
                    status["remote"],
                    min(start or now, now),
                    now,
                    rx - rx_start,
                    tx - tx_start,
                    rx_start,
                    tx_start,
                ),
            )
        conn.execute(
            "INSERT OR REPLACE INTO counters (instance, public_key, rx, tx) VALUES (?, ?, ?, ?)",
            (key[0], key[1], rx, tx),
        )
    # the counters of the peers that are gone start from zero when they come back
    for key in counters:
        if key not in peers:
            conn.execute("DELETE FROM counters WHERE instance = ? AND public_key = ?", key)
    conn.commit()


def _filters(instances=None, q="", start_time=0, accounts=None):
    conditions = []
    params = {}
    if instances:
        conditions.append("instance IN (" + ",".join(f":instance{i}" for i in range(len(instances))) + ")")
        params.update({f"instance{i}": instance for i, instance in enumerate(instances)})
    if start_time:
        conditions.append("start_time >= :start_time")
        params["start_time"] = start_time
    if accounts:
        conditions.append("peer_name IN (" + ",".join(f":account{i}" for i in range(len(accounts))) + ")")
        params.update({f"account{i}": account for i, account in enumerate(accounts)})
    if q:
        conditions.append(
            "(peer_name LIKE :q OR user LIKE :q OR virtual_ip_addr LIKE :q OR remote_ip_addr LIKE :q OR instance LIKE :q)"
        )
        params["q"] = f"%{q}%"
    return ("WHERE " + " AND ".join(conditions)) if conditions else "", params


def _address_key(value):
    try:
        address = ipaddress.ip_address(value or "")
        return (address.version, int(address))
    except ValueError:
        return (0, 0)


def _connection(row, now):
    instance, peer, name, user, virtual_ip, remote_ip, start, ended, received, sent = row
    return {
        "instance": instance,
        "peer": peer,
        "account": name,
        "user": user or "",
        "virtualIpAddress": virtual_ip,
        "remoteIpAddress": remote_ip,
        "startTime": start,
        # None while connected
        "endTime": ended,
        "duration": (ended if ended is not None else now) - start,
        "connected": ended is None,
        "bytesReceived": received,
        "bytesSent": sent,
    }


def query(
    conn,
    instances=None,
    q="",
    start_time=0,
    accounts=None,
    page=1,
    per_page=10,
    sort_by="startTime",
    desc=True,
    now=None,
):
    """
    Read a page of the connection history, with the same fields as the history of OpenVPN Road Warrior.

    Arguments:
      - conn -- the history, see `open_readonly`; None for an empty history
      - instances -- the servers to include, all if empty
      - q -- text in the name of the peer, its user, its addresses or its server
      - start_time -- only the connections started from this time, seconds since 1970
      - accounts -- the names of the peers to include, all if empty
      - page, per_page -- the page to read
      - sort_by -- `account`, `user`, `instance`, `startTime`, `endTime`, `duration`, `virtualIpAddress`,
        `remoteIpAddress`, `bytesReceived` or `bytesSent`
      - desc -- the descending order
      - now -- the current time, seconds since 1970

    Returns:
      - a dictionary with `connections`, the page; `results`, the connections that match; `total`, all of them;
        `current_page`, `last_page`, `per_page`; `filters`, the names of the peers and the servers in the history
    """
    now = int(time.time() if now is None else now)
    result = {"connections": [], "current_page": page, "last_page": 1, "per_page": per_page, "total": 0, "results": 0}
    result["filters"] = {"accounts": [], "instances": []}
    if conn is None:
        return result
    where, params = _filters(instances, q, start_time, accounts)
    params.update({"now": now, "stale": STALE_AFTER})
    result["total"] = conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
    result["results"] = conn.execute(f"SELECT COUNT(*) FROM connections {where}", params).fetchone()[0]
    result["last_page"] = max(1, (result["results"] + per_page - 1) // per_page)
    offset = (page - 1) * per_page
    direction = "DESC" if desc else "ASC"
    if sort_by in SORT_ADDRESSES:
        rows = conn.execute(f"SELECT {COLUMNS} FROM connections {where}", params).fetchall()
        rows.sort(key=lambda row: _address_key(row[SORT_ADDRESSES[sort_by]]), reverse=desc)
        rows = rows[offset : offset + per_page]
    else:
        order = SORT_COLUMNS.get(sort_by, SORT_COLUMNS["startTime"])
        params.update({"limit": per_page, "offset": offset})
        rows = conn.execute(
            f"SELECT {COLUMNS} FROM connections {where} ORDER BY {order} {direction}, start_time {direction} "
            "LIMIT :limit OFFSET :offset",
            params,
        ).fetchall()
    result["connections"] = [_connection(row, now) for row in rows]
    result["filters"]["accounts"] = sorted(
        row[0] for row in conn.execute("SELECT DISTINCT peer_name FROM connections WHERE peer_name IS NOT NULL")
    )
    result["filters"]["instances"] = sorted(row[0] for row in conn.execute("SELECT DISTINCT instance FROM connections"))
    return result


def export_csv(conn, path, timezone="UTC", names=None, instances=None, now=None):
    """
    Write the connection history in a CSV file, newest first.

    Arguments:
      - conn -- the history, see `open_readonly`; None for an empty history
      - path -- the CSV file
      - timezone -- the time zone of the times, UTC if it isn't known
      - names -- the names of the servers, by interface
      - instances -- the servers to include, all if empty
      - now -- the current time, seconds since 1970
    """
    now = int(time.time() if now is None else now)
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        # also without the time zone database
        timezone, zone = "UTC", UTC
    names = names or {}

    def local(timestamp):
        return datetime.fromtimestamp(timestamp, tz=zone).strftime("%Y-%m-%d %H:%M:%S") if timestamp else ""

    with open(path, "w", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            [
                "Server",
                "Peer",
                "User",
                f"Started ({timezone})",
                f"Ended ({timezone})",
                "Duration (seconds)",
                "Virtual IP",
                "Remote IP",
                "Received (bytes)",
                "Sent (bytes)",
            ]
        )
        if conn is None:
            return
        where, params = _filters(instances)
        params.update({"now": now, "stale": STALE_AFTER})
        for row in conn.execute(f"SELECT {COLUMNS} FROM connections {where} ORDER BY start_time DESC", params):
            item = _connection(row, now)
            writer.writerow(
                [
                    names.get(item["instance"], item["instance"]),
                    item["account"],
                    item["user"],
                    local(item["startTime"]),
                    local(item["endTime"]),
                    item["duration"],
                    item["virtualIpAddress"],
                    item["remoteIpAddress"],
                    item["bytesReceived"],
                    item["bytesSent"],
                ]
            )
