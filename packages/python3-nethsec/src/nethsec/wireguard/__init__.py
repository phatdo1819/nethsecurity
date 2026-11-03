#!/usr/bin/python3

#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
The traffic between the peers of the WireGuard servers.

Each server has a firewall zone of its own, `<instance>vpn`, made by `ns.wireguard` with
`nethsec.firewall.add_trusted_zone`: it reaches lan and wan and rejects the rest, the traffic between two peers of
the server too (fw4 applies the forward policy of a zone to the traffic that goes back into it). Two options of the
server interface open more:

  - `ns_client_to_client`: a rule accepts the traffic from the zone of the server to itself, so the peers of the
    server reach each other
  - `ns_reachable_servers`, a list of servers: a forwarding from the zone of the server to the zone of each one.
    It's one way: the peers of the server start connections to the peers of the listed servers, and the answers
    pass as established traffic. For the other way, the other server lists this one

The rule and the forwardings are linked to the server (`ns_link network/<instance>`), so deleting the server deletes
them. With a login (`nethsec.wgauth`), the gate still lets the traffic through only between logged-in peers.

The configuration of a peer must route the networks of the other servers: `linked_networks` gives the networks of
the servers linked to its server, either way, as the answers of the peers of a listed server go back through their
own tunnel. See docs/design/wireguard_peer_traffic.md.
"""

import ipaddress

from nethsec import utils

ZONE_SUFFIX = "vpn"


def list_servers(uci):
    """
    List the WireGuard servers.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - the names of the network interfaces of the servers, in the order of the configuration
    """
    interfaces = utils.get_all_by_type(uci, "network", "interface")
    return [
        name
        for name, interface in interfaces.items()
        if interface.get("proto") == "wireguard" and interface.get("ns_type", "") == "server"
    ]


def get_zone(instance):
    """
    Return the name of the firewall zone of a server.

    Arguments:
      - instance -- the network interface of the server

    Returns:
      - the zone name, like `wg1vpn`
    """
    return f"{instance}{ZONE_SUFFIX}"


def get_client_to_client_rule(instance):
    """
    Return the firewall section of the rule accepting the traffic between the peers of a server.

    Arguments:
      - instance -- the network interface of the server

    Returns:
      - the firewall section name
    """
    return f"ns_{instance}_client_to_client"


def get_forwarding(instance, target):
    """
    Return the firewall section of the forwarding from the peers of a server to the peers of another one.

    Arguments:
      - instance -- the network interface of the server whose peers start the connections
      - target -- the network interface of the server they reach

    Returns:
      - the firewall section name
    """
    return f"ns_{instance}_to_{target}"


def allows_client_to_client(uci, instance):
    """
    Check if the peers of a server can reach each other.

    Arguments:
      - uci -- EUci pointer
      - instance -- the network interface of the server

    Returns:
      - True if the `ns_client_to_client` option is on; a value that isn't a boolean counts as off
    """
    return uci.get("network", instance, "ns_client_to_client", dtype=bool, default=False)


def get_reachable_servers(uci, instance, servers=None):
    """
    Return the servers whose peers the peers of a server can reach.

    Arguments:
      - uci -- EUci pointer
      - instance -- the network interface of the server
      - servers -- the servers, as returned by list_servers (optional)

    Returns:
      - the servers listed in the `ns_reachable_servers` option that still exist, without the server itself and
        without duplicates, in the order of the list
    """
    if servers is None:
        servers = list_servers(uci)
    ret = []
    for target in uci.get("network", instance, "ns_reachable_servers", dtype=str, list=True, default=[]):
        if target != instance and target in servers and target not in ret:
            ret.append(target)
    return ret


def linked_servers(uci, instance):
    """
    Return the servers linked to a server, either way.

    Arguments:
      - uci -- EUci pointer
      - instance -- the network interface of the server

    Returns:
      - the servers that the server lists, then the ones that list it, in the order of the configuration
    """
    servers = list_servers(uci)
    reachable = get_reachable_servers(uci, instance, servers)
    ret = []
    for server in servers:
        if server == instance:
            continue
        if server in reachable or instance in get_reachable_servers(uci, server, servers):
            ret.append(server)
    return ret


def linked_networks(uci, instance):
    """
    Return the networks that the configuration of a peer of a server routes besides the network of the server.

    The peers of a server reach the peers of the servers it lists, and they answer the peers of the servers that
    list it: both need a route through the tunnel.

    Arguments:
      - uci -- EUci pointer
      - instance -- the network interface of the server

    Returns:
      - the networks of the linked servers, like `10.20.0.0/24`, without duplicates and without the network of the
        server
    """
    own = uci.get("network", instance, "ns_network", default="")
    ret = []
    for server in linked_servers(uci, instance):
        network = uci.get("network", server, "ns_network", default="")
        try:
            ipaddress.ip_network(network)
        except ValueError:
            continue
        if network != own and network not in ret:
            ret.append(network)
    return ret


def remove_server(uci, instance):
    """
    Remove a server from the lists of the other servers: call it before deleting the server.
    The changes are saved, not committed.

    Arguments:
      - uci -- EUci pointer
      - instance -- the network interface of the server

    Returns:
      - the servers whose list changed
    """
    changed = []
    for server in list_servers(uci):
        if server == instance:
            continue
        current = list(uci.get("network", server, "ns_reachable_servers", dtype=str, list=True, default=[]))
        if instance not in current:
            continue
        remaining = [target for target in current if target != instance]
        if remaining:
            uci.set("network", server, "ns_reachable_servers", remaining)
        else:
            uci.delete("network", server, "ns_reachable_servers")
        changed.append(server)
    uci.save("network")
    return changed


def _zones(uci):
    return {zone.get("name") for zone in utils.get_all_by_type(uci, "firewall", "zone").values()}


def _set_section(uci, section, section_type, options):
    # create or update a section, touching only the options that changed: True if anything changed
    changed = False
    if uci.get("firewall", section, default=None) != section_type:
        if uci.get("firewall", section, default=None) is not None:
            uci.delete("firewall", section)
        uci.set("firewall", section, section_type)
        changed = True
    for option, value in options.items():
        if isinstance(value, list):
            current = list(uci.get("firewall", section, option, dtype=str, list=True, default=[]))
        else:
            current = uci.get("firewall", section, option, default=None)
        if current != value:
            uci.set("firewall", section, option, value)
            changed = True
    return changed


def sync_peer_traffic(uci):
    """
    Apply the `ns_client_to_client` and `ns_reachable_servers` options of all the servers: create, update or remove
    the firewall rules and forwardings. Call it after adding, changing or deleting a server.
    Nothing is made for a zone that doesn't exist. The changes are saved, not committed.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - the firewall sections created, changed or removed
    """
    servers = list_servers(uci)
    zones = _zones(uci)
    wanted = {}
    for instance in servers:
        zone = get_zone(instance)
        if zone not in zones:
            continue
        link = f"network/{instance}"
        if allows_client_to_client(uci, instance):
            wanted[get_client_to_client_rule(instance)] = (
                "rule",
                {
                    "name": f"Allow-WireGuard-{instance}-client-to-client",
                    "src": zone,
                    "dest": zone,
                    "proto": "all",
                    "target": "ACCEPT",
                    "enabled": "1",
                    "ns_tag": ["automated"],
                    "ns_link": link,
                },
            )
        for target in get_reachable_servers(uci, instance, servers):
            if get_zone(target) not in zones:
                continue
            wanted[get_forwarding(instance, target)] = (
                "forwarding",
                {
                    "name": f"WireGuard-{instance}-to-{target}",
                    "src": zone,
                    "dest": get_zone(target),
                    "ns_tag": ["automated"],
                    "ns_link": link,
                },
            )

    changed = []
    for section, (section_type, options) in wanted.items():
        if _set_section(uci, section, section_type, options):
            changed.append(section)

    # the sections of the options turned off, of the servers no longer listed and of the deleted servers
    prefixes = tuple(f"ns_{instance}_to_" for instance in servers)
    managed = {get_client_to_client_rule(instance) for instance in servers}
    for section in list(uci.get("firewall")):
        if section in wanted:
            continue
        if section in managed or _is_forwarding_of(uci, section, prefixes):
            uci.delete("firewall", section)
            changed.append(section)

    uci.save("firewall")
    return changed


def _is_forwarding_of(uci, section, prefixes):
    if not prefixes or not section.startswith(prefixes):
        return False
    return uci.get("firewall", section, default=None) == "forwarding"
