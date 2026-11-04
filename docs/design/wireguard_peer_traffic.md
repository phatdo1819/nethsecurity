---
layout: default
title: WireGuard traffic between peers
parent: Design
---

# WireGuard traffic between peers

**Status:** implemented in `ns.wireguard` and `nethsec.wireguard`, not released yet.

* TOC
{:toc}

## Summary

By default the peers of a WireGuard server reach the firewall, the LAN and the internet, but not each other, and not
the peers of the other WireGuard servers. Two options of a server open more:

- **Traffic between peers** (`client_to_client`): the peers of the server can connect to each other.
- **Access to the peers of other servers** (`reachable_servers`): the peers of the server can connect to the peers of
  the servers listed. It's one way: for the other way, the other server lists this one.

Both are off by default, so nothing changes for the existing servers.

## Why the traffic is blocked

`ns.wireguard add-server` gives each server a firewall zone of its own, `<instance>vpn` (`wg1vpn`), made by
`nethsec.firewall.add_trusted_zone`:

- input and output `ACCEPT`, forward `REJECT`;
- forwardings to `lan` and `wan`, and from `lan`.

fw4 applies the forward policy of a zone to the traffic that goes back into the same zone (the `reject_to_wg1vpn`
jump at the end of the `forward_wg1vpn` chain), so the traffic from one peer to another peer of the same server is
rejected. The zones of two servers have no forwarding between them, so the traffic between their peers is rejected
too.

The configurations of the peers already route the network of their server (`AllowedIPs` has the server network, or
`0.0.0.0/0`), so the traffic between two peers of a server reaches the firewall: only the firewall blocks it.

## What the options make

`nethsec.wireguard.sync_peer_traffic()` creates, updates or removes the firewall sections from the options of all
the servers. `ns.wireguard` calls it after `add-server`, `edit-server` and `delete-server`. The sections are tagged
`automated` and linked to their server (`ns_link network/<instance>`), so `delete-server` deletes them with the
server.

| Option, on the server interface | Firewall section | What it does |
| --- | --- | --- |
| `ns_client_to_client` `1` | rule `ns_<instance>_client_to_client`, `src` and `dest` the zone of the server, `proto all`, `ACCEPT` | the peers of the server connect to each other |
| `ns_reachable_servers` list, like `wg2` | forwarding `ns_<instance>_to_<target>`, from the zone of the server to the zone of the target | the peers of the server start connections to the peers of the target |

A rule, not the forward policy of the zone, so the zone keeps the settings of `add_trusted_zone` and an
administrator who changes the zone doesn't change the option. `proto all`: without it fw4 accepts only TCP and UDP,
and ping fails.

### One way

A forwarding accepts the new connections from its source zone only. The answers of the target pass as established
traffic (the `ct state established,related accept` of the fw4 forward chain), so one entry is enough for the peers of
a server to use the services of the peers of another one, and the peers of the other server can't start connections
back. The user interface lists the other servers one per row, with a checkbox, and says it under the list: "For
the other way, check this server in their settings."

### The routes of the peers

A peer that doesn't route all its traffic sends only the networks of its `AllowedIPs` through the tunnel. So the
configuration of a peer of a server also routes, after the local networks and the server network, the networks of
the servers linked to its server (`nethsec.wireguard.linked_networks`):

- the servers it lists: its peers start the connections;
- the servers that list it: its peers answer, and the answers must go back through the tunnel, not through the
  internet connection of the peer.

The configurations are written by `list-servers` from the current settings, so the new routes are there at once. The
peers that already have their configuration need it again; the peers that route all their traffic (`0.0.0.0/0`)
don't. The drawer of the server says it when the list changes.

## With the login

The gate of `ns-wgauth` (the `inet ns_wgauth` table, see [WireGuard user login](wireguard_user_auth.md)) runs before
fw4 and drops the traffic from and to the peers of a gated server that aren't logged in, in both directions:

- from a peer of a gated server, only once its user is logged in;
- to a peer of a gated server, only once its user is logged in.

So with the options on, two peers connect only when both are logged in (when their servers require the login), and
the gate needs no change. The options don't change the input traffic, that the gate restricts to the login page
before the login.

## Lifecycle

| Event | What happens |
| --- | --- |
| `add-server` with the options | the server, its zone, then the sections |
| `edit-server` with the options | the options are saved and the sections follow; missing options keep their values |
| `edit-server` without them | nothing changes: the clients that don't know the options keep them |
| `delete-server` | the server leaves the lists of the other servers (`nethsec.wireguard.remove_server`), its sections go with its `ns_link`, and the forwardings of the other servers to its zone are removed |
| a listed server doesn't exist or has no zone | no section for it |

Saving a server restarts its interface, as before (the `restart-wireguard.py` post-commit hook): the peers of the
server reconnect within seconds, and the login sessions stay. Removing a deleted server from the lists of the other
servers changes them too, so they restart as well.

## API

- `add-server`, `edit-server`: `client_to_client` (boolean) and `reachable_servers` (list of server instances).
  Validation errors: `client_to_client` `invalid`; `reachable_servers` `invalid`, `server_not_found`,
  `duplicate_server`, `same_server`.
- `list-servers`: the two fields on every server.
- `get-instance-defaults`: `peer_traffic` `true`, so a client shows the options only on a firewall that knows them.

See the [ns-api README](../../packages/ns-api/README.md) for the details.
