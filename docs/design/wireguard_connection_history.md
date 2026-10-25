---
layout: default
title: WireGuard connection history
parent: Design
---

# WireGuard connection history

**Status:** implemented in `nethsec.wghistory` and `ns.wireguard`, not released yet.

* TOC
{:toc}

## Summary

The history of the connections of the peers of the WireGuard servers, like the one of OpenVPN Road Warrior: who
was connected, from which public address, when, for how long, and how many bytes. The UI shows it in the
*Connections* tab of the WireGuard page, and exports it as CSV.

## How connections are found

WireGuard has no connections and no hooks to run when a peer comes or goes: a peer is there while its handshakes keep
coming. A peer that sends anything, its keepalive too, makes a new handshake at least every 2 minutes, and without a
handshake for 3 minutes (`REJECT_AFTER_TIME`) no data can pass.

`/usr/libexec/wireguard-history` runs every minute from cron (`99-ns-api.wireguard-history` adds the line to
`/etc/crontabs/root`), reads `wg show all dump`, and calls `nethsec.wghistory.record`. For each peer of a server:

- a peer with a handshake in the last 3 minutes and no open row starts a connection, from the time of that handshake
- an open row follows the byte counters of the peer; the time of the last change is its `last_seen`
- a row ends at its `last_seen` when:
  - the latest handshake is older than 3 minutes: the peer left
  - the peer comes from another public address: it moved to another network, a new row starts
  - its counters are lower than a minute before: the interface restarted, for example after a change of the
    configuration, a new row starts
  - the peer isn't there anymore: the interface is down, or the peer was removed
  - the row wasn't updated for 5 minutes: the recorder didn't run, a new row starts

So the times are precise to the minute. The bytes of a row are the ones of its counters since the row started: the
counters of WireGuard count from the time the interface came up, so the history keeps the counters of the last
minute for each peer (table `counters`).

The peers of the client tunnels (`ns_type` `tunnel`) have no history. Without any WireGuard server and without a
history, the recorder does nothing.

## Storage

`connections.db`, a SQLite database, in `<data storage>/wireguard/` when the firewall has a data storage
(`fstab.ns_data.target`), like the history of OpenVPN; else in `/var/wireguard/`, in RAM: lost at reboot. Table
`connections`:

| Column | |
|---|---|
| `instance` | the server interface, e.g. `wg1` |
| `peer`, `public_key` | the section and the key of the peer |
| `peer_name`, `user`, `virtual_ip_addr` | the name, the linked user and the reserved IP of the peer, updated while connected |
| `remote_ip_addr` | the public IP the peer comes from |
| `start_time`, `end_time`, `last_seen` | seconds since 1970; `end_time` is NULL while connected |
| `bytes_received`, `bytes_sent` | from the peer, to the peer |
| `rx_start`, `tx_start` | the counters of WireGuard when the row started |

The queries consider ended, at its `last_seen`, an open row not updated for 5 minutes: the recorder stopped, a
reboot with the history on a data storage.

## API

`ns.wireguard connection-history` reads a page, with the filters and the sorting of the history of OpenVPN Road
Warrior, and `connection-history-csv` writes all of it in the downloads of `ns-api-server`. See the
[README](../../packages/ns-api/README.md) of ns-api.

## Limits

- An idle peer without a keepalive makes no handshakes: after 3 minutes it's out of the history, and back as a new
  connection when it sends again. The configurations of the firewall have a keepalive of 25 seconds.
- A connection shorter than a minute is recorded once seen, with the time of its handshake.
- The history has no limit of size, like the one of OpenVPN: a row for each connection.
