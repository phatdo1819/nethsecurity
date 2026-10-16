#!/usr/bin/python3

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Library for common VPN functions.
"""

import os
import json
import ipaddress
import random
import re
import struct
import socket
import subprocess
from nethsec import utils

def get_local_networks(u):
    """
    Return a list of local networks.

    Arguments:
      - u -- EUci instance

    Returns:
      - a list of local networks
    """
    ret = set()
    for l in utils.get_all_lan_devices(u):
        try:
            data = json.loads(subprocess.run(["ip", "--json", "address", "show", "dev", l], capture_output=True, text=True, check=True).stdout)
            if len(data) > 0:
                for addr in data[0].get('addr_info', []):
                    if addr.get("local", None) and addr.get("family", None) == "inet": # ipv4 only
                        # skip bond management address
                        if addr.get("local").startswith("127"):
                            continue
                        net = ipaddress.ip_interface(f'{addr.get("local")}/{addr.get("prefixlen")}').network
                        ret.add(f'{net}')
        except:
            continue
    return list(ret)

def get_public_addresses(u):
    """
    Return a list of public addresses.

    Arguments:
      - u -- EUci instance

    Returns:
      - a list of public addresses
    """
    ret = {}
    for w in utils.get_all_wan_devices(u):
        try:
             data = json.loads(subprocess.run(["ip", "--json", "address", "show", "dev", w], capture_output=True, text=True, check=True).stdout)
        except:
            continue
        if len(data) > 0:
            for addr in data[0].get('addr_info', []):
                if addr.get("local", None):
                    try:
                        res = subprocess.run([
                            "/usr/bin/dig",
                            "-b",
                            addr.get("local"),
                            "+short",
                            "+time=1",
                            "myip.opendns.com",
                            "@resolver1.opendns.com"
                        ],
                        capture_output=True, text=True, check=True)
                        ret[res.stdout.strip()] = 1
                    except:
                        pass
    return list(ret.keys())

def to_cidr(netmask):
    """
    Convert a netmask to CIDR notation.

    Arguments:
      - netmask -- netmask in dotted decimal notation

    Returns:
      - CIDR notation

    """
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def to_netmask(prefix):
    """
    Convert a CIDR notation to netmask.

    Arguments:
      - prefix -- CIDR notation

    Returns:
      - netmask in dotted decimal notation
    """
    return socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - int(prefix))) & 0xffffffff))

def generate_random_network(u):
    """
    Generate a random network.

    Arguments:
      - u -- EUci instance

    Returns:
     - a random unused network
    """
    network = random_network()
    while is_used_network(u, network):
        network = random_network()
    return network

def random_network():
    """
    Generate a random private network address.

    Returns:
      - a random private network address
    """
    return f"10.{random.randint(0, 254)}.{random.randint(0, 254)}.0/24"

def is_used_network(u, network):
    """
    Check if a network is already used by another OpenVPN.

    Arguments:
      - u -- EUci instance
      - network -- network to check

    Returns:
      - True if the network is already used, False otherwise
    """
    try:
        openvpn = u.get_all('openvpn')
    except:
        return False

    for v in openvpn:
        ifconfig = u.get('openvpn', v, 'ifconfig', default="")
        if ifconfig:
            ifnet = f'{ifconfig.split(" ")[0]}/24' # assume /24
            if ipaddress.ip_network(ifnet, strict=False) == ipaddress.ip_network(network):
                return True

        server = opt2cidr(u.get('openvpn', v, 'server', default=""))
        if server and server == network:
            return True

        server_bridge = opt2cidr(u.get('openvpn', v, 'server_bridge', default=""))
        if server_bridge:
            if ipaddress.ip_network(server_bridge, strict=False) == ipaddress.ip_network(network):
                return True
    return False

def opt2cidr(opt):
    """
    Convert an OpenVPN option to CIDR notation.

    Arguments:
      - opt -- OpenVPN option

    Returns:
      - CIDR notation
    """
    try:
        tmp = opt.split(" ")
        return f'{tmp[0]}/{to_cidr(tmp[1])}'
    except:
        return ""
    

def list_cipher():
    """
    Return a list of OpenVPN ciphers.

    Returns:
      - a list of OpenVPN ciphers, each element is a dicttionary with the following keys:
          - name: cipher name
          - description: cipher description (weak or strong)
    """
    ret = []
    try:
        result = subprocess.run(['/usr/sbin/openvpn', '--show-ciphers'], capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()

        for line in output_lines:
            if '(' in line:
                description = 'weak'
                tmp = line.split()
                cipher_name = tmp[0]
                try:
                    bits = int(cipher_name.split("-")[1])
                except:
                    bits = 0
                if bits in [192, 256, 384, 512]:
                    description = 'strong'
                ret.append({'name': cipher_name, 'description': description})
    except:
        return {"ciphers": []}
    return {"ciphers": ret}

def list_digest():
    """
    Return a list of OpenVPN digests.

    Returns:
      - a list of OpenVPN digests, each element is a dicttionary with the following keys:
        - name: digest name
        - description: digest description (weak or strong)
    """
    ret = []
    try:
        result = subprocess.run(['/usr/sbin/openvpn', '--show-digests'], capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()

        for line in output_lines:
            if 'bit' in line:
                description = 'weak'
                tmp = line.split()
                if tmp[1] in ['224', '256', '384', '512', 'whirlpool']:
                    description = 'strong'
                ret.append({'name': tmp[0], 'description': description})
    except:
        return {"digests": []}
    return {"digests": ret}

def generate_random_port(uci, limit_min, limit_max):
    '''
    Generate a random port.

    Arguments:
        - uci -- EUci instance
        - limit_min -- minimum port number
        - limit_max -- maximum port number

    Returns:
        - a random port number
    '''
    port = random.randint(limit_min, limit_max)
    while is_used_port(uci, port):
        port = random.randint(limit_min, limit_max)
    return port

def is_used_port(uci, port, exclude=None):
    '''
    Check if a port is already used by another OpenVPN.

    Arguments:
        - uci -- EUci instance
        - port -- port to check
        - exclude -- optional OpenVPN instance name to ignore, useful when
          validating the new port of an already existing instance

    Returns:
        - True if the port is already used, False otherwise
    '''
    for v in uci.get_all('openvpn'):
        if v == exclude:
            continue
        rport = int(uci.get('openvpn', v, 'port', default="0"))
        lport = int(uci.get('openvpn', v, 'lport', default="0"))
        if port == rport or port == lport:
            return True
    return False

def list_connected_clients(openvpninstance, type="subnet"):
    """
    List connected clients.

    Arguments:
        - openvpninstance -- OpenVPN instance name
        - type -- type of list (subnet or p2p)

    Returns:
        - a list of connected clients
    """
    try:
        p = subprocess.run(["/usr/bin/openvpn-status", "-t", type, f"/var/run/openvpn_{openvpninstance}.socket"], check=True, capture_output=True, text=True)
    except:
        return {}
    return json.loads(p.stdout)


def find_overlapping_network(uci, network, exclude=None):
    """
    Search for an OpenVPN server using a network overlapping the given one.

    Arguments:
      - uci -- EUci instance
      - network -- network to check, in CIDR notation
      - exclude -- optional OpenVPN instance name to ignore

    Returns:
      - the name of the first conflicting instance, None if there are no conflicts
    """
    target = ipaddress.ip_network(network, strict=False)
    try:
        sections = uci.get_all('openvpn')
    except:
        return None
    for v in sections:
        if v == exclude:
            continue
        server = opt2cidr(uci.get('openvpn', v, 'server', default=""))
        if server and ipaddress.ip_network(server, strict=False).overlaps(target):
            return v
    return None


def find_conflicting_port(uci, port, proto, exclude=None):
    """
    Search for an OpenVPN server listening on the same port with the same protocol.
    Only servers are checked: the port of a client is the remote one.

    Arguments:
      - uci -- EUci instance
      - port -- port to check
      - proto -- protocol to check (udp or tcp)
      - exclude -- optional OpenVPN instance name to ignore

    Returns:
      - the name of the first conflicting instance, None if there are no conflicts
    """
    try:
        sections = uci.get_all('openvpn')
    except:
        return None
    for v in sections:
        if v == exclude:
            continue
        if not uci.get('openvpn', v, 'server', default='') and not uci.get('openvpn', v, 'server_bridge', default=''):
            continue
        if str(uci.get('openvpn', v, 'port', default='1194')) != str(port):
            continue
        if uci.get('openvpn', v, 'proto', default='udp')[:3] == str(proto)[:3]:
            return v
    return None


def list_roadwarrior_instances(uci):
    """
    List the Road Warrior instances created by NethSecurity.

    Arguments:
      - uci -- EUci instance

    Returns:
      - a list of instance names
    """
    ret = []
    instances = utils.get_all_by_type(uci, "openvpn", "openvpn") or {}
    for name, instance in instances.items():
        tag = instance.get("ns_tag")
        if tag and "automated" in tag:
            ret.append(name)
    return ret


def next_instance_number(uci):
    """
    Return the lowest instance number not used by any Road Warrior instance.

    The number is used to build the instance name (ns_roadwarrior<N>), the network
    device (tunrw<N>/taprw<N>) and the firewall service name (OpenVPNRW<N>), so it
    must be unique even if a previous instance has been removed.

    Arguments:
      - uci -- EUci instance

    Returns:
      - the instance number
    """
    used = set()
    for name in list_roadwarrior_instances(uci):
        match = re.search(r"\d+", name)
        if match:
            used.add(int(match.group()))
    number = 1
    while number in used or uci.get("openvpn", utils.get_id(f"roadwarrior{number}"), default=None) is not None:
        number += 1
    return number


# Per-instance user membership
#
# A user can be authorized on more than one Road Warrior instance, for example when
# the same user database is shared by two instances. The following user options
# keep the state of each instance independent:
#
#   - openvpn_instances: list of instances the user belongs to
#   - openvpn_disabled: list of instances where the user is disabled (subset of openvpn_instances)
#
# The openvpn_enabled option is still maintained (1 if the user is enabled on at least
# one instance) for the code reading it directly. Users without openvpn_instances
# are legacy users: they are authorized on all the instances using their database
# if openvpn_enabled is 1. See migrate_user_memberships().
#
# The openvpn_ipaddr and openvpn_2fa options are shared between all the instances:
# a reserved IP address is applied only on the instance whose network contains it.

def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def get_user_instances(user):
    """
    Return the instances a user belongs to.

    Arguments:
      - user -- user object, as returned by users.get_user_by_name

    Returns:
      - a list of instance names, None for legacy users without explicit membership
    """
    if user.get('openvpn_instances') is None:
        return None
    return _as_list(user.get('openvpn_instances'))


def is_user_member(user, instance):
    """
    Check if a user belongs to an instance, regardless of being enabled.

    Arguments:
      - user -- user object, as returned by users.get_user_by_name
      - instance -- OpenVPN instance name

    Returns:
      - True if the user belongs to the instance
    """
    instances = get_user_instances(user)
    if instances is None:
        return 'openvpn_enabled' in user
    return instance in instances


def is_user_enabled(user, instance):
    """
    Check if a user is allowed to connect to an instance.

    Arguments:
      - user -- user object, as returned by users.get_user_by_name
      - instance -- OpenVPN instance name

    Returns:
      - True if the user belongs to the instance and is not disabled
    """
    instances = get_user_instances(user)
    if instances is None:
        return user.get('openvpn_enabled', '0') == '1'
    return instance in instances and instance not in _as_list(user.get('openvpn_disabled'))


def get_user_membership(uci, user):
    """
    Return the instances a user belongs to and the ones where it is disabled.
    Legacy users, without explicit membership, belong to all the instances using their database.

    Arguments:
      - uci -- EUci instance
      - user -- user object, as returned by users.get_user_by_name

    Returns:
      - a tuple of two lists: the instances and the disabled instances
    """
    instances = get_user_instances(user)
    if instances is not None:
        return instances, [i for i in _as_list(user.get('openvpn_disabled')) if i in instances]
    # legacy user: authorized on all the instances using its database
    if 'openvpn_enabled' not in user:
        return [], []
    instances = [
        i for i in list_roadwarrior_instances(uci)
        if uci.get('openvpn', i, 'ns_user_db', default='') == user.get('database', '')
    ]
    disabled = instances if user.get('openvpn_enabled') != '1' else []
    return instances, list(disabled)


def _delete_option(uci, user_id, option):
    try:
        uci.delete('users', user_id, option)
    except:
        pass


def _save_membership(uci, user_id, instances, disabled):
    instances = list(dict.fromkeys(instances))
    disabled = [i for i in dict.fromkeys(disabled) if i in instances]
    if instances:
        uci.set('users', user_id, 'openvpn_instances', instances)
        if disabled:
            uci.set('users', user_id, 'openvpn_disabled', disabled)
        else:
            _delete_option(uci, user_id, 'openvpn_disabled')
        enabled = any(i not in disabled for i in instances)
        uci.set('users', user_id, 'openvpn_enabled', '1' if enabled else '0')
    else:
        for option in ['openvpn_instances', 'openvpn_disabled', 'openvpn_enabled', 'openvpn_ipaddr', 'openvpn_2fa']:
            _delete_option(uci, user_id, option)


def add_user_instance(uci, user, instance, enabled=True):
    """
    Add a user to an instance, or change its status if already there.
    The changes are not committed.

    Arguments:
      - uci -- EUci instance
      - user -- user object, as returned by users.get_user_by_name
      - instance -- OpenVPN instance name
      - enabled -- if False the user is added as disabled
    """
    instances, disabled = get_user_membership(uci, user)
    if instance not in instances:
        instances.append(instance)
    disabled = [i for i in disabled if i != instance]
    if not enabled:
        disabled.append(instance)
    _save_membership(uci, user['id'], instances, disabled)


def set_user_instance_enabled(uci, user, instance, enabled):
    """
    Enable or disable a user on a single instance.
    The changes are not committed.

    Arguments:
      - uci -- EUci instance
      - user -- user object, as returned by users.get_user_by_name
      - instance -- OpenVPN instance name
      - enabled -- True to enable the user, False to disable it
    """
    add_user_instance(uci, user, instance, enabled)


def remove_user_instance(uci, user, instance):
    """
    Remove a user from an instance. All OpenVPN options are removed from the user
    when it does not belong to any other instance.
    The changes are not committed.

    Arguments:
      - uci -- EUci instance
      - user -- user object, as returned by users.get_user_by_name
      - instance -- OpenVPN instance name

    Returns:
      - True if the user does not belong to any instance anymore
    """
    instances, disabled = get_user_membership(uci, user)
    if instance in instances:
        instances = [i for i in instances if i != instance]
    elif instances:
        # not a member of this instance, nothing to do
        return False
    _save_membership(uci, user['id'], instances, disabled)
    return len(instances) == 0


def get_instance_network(uci, instance):
    """
    Return the network of the clients of a Road Warrior instance.

    Arguments:
      - uci -- EUci instance
      - instance -- OpenVPN instance name

    Returns:
      - an ipaddress network object, None if the instance has no valid server network
    """
    server = uci.get('openvpn', instance, 'server', default='')
    if not server:
        server = uci.get('openvpn', instance, 'server_bridge', default='')
    parts = server.split(" ")
    if len(parts) < 2 or not parts[0]:
        return None
    try:
        return ipaddress.ip_network(f'{parts[0]}/{parts[1]}', strict=False)
    except ValueError:
        return None


# Traffic between Road Warrior instances
#
# All the instances share the rwopenvpn zone, which rejects the traffic inside the zone:
# by default the clients of an instance can't reach the clients of another instance.
# When the ns_inter_server option is enabled on two or more tun instances, each of them gets:
#
#   - a pushed route for the network of every other enabled instance; the routes added this way
#     are listed in the ns_inter_server_route option, so they are not mistaken for local networks
#   - a firewall rule (<instance>_inter_server) accepting the traffic from its network to the
#     networks of the other enabled instances
#
# The traffic between the clients of the same instance is not affected (see client_to_client and
# sync_client_to_client_traffic).

INTER_SERVER_ZONE = 'rwopenvpn'


def _delete(uci, config, section, option):
    try:
        uci.delete(config, section, option)
    except:
        pass


def _set_if_changed(uci, config, section, option, value):
    if isinstance(value, list):
        current = _as_list(uci.get(config, section, option, list=True, default=None))
    else:
        current = uci.get(config, section, option, default=None)
    if current != value:
        uci.set(config, section, option, value)


def is_inter_server_enabled(uci, instance):
    """
    Check if the clients of an instance can talk to the clients of the other Road Warrior instances.

    Arguments:
      - uci -- EUci instance
      - instance -- OpenVPN instance name

    Returns:
      - True if the ns_inter_server option is enabled and the instance uses a tun device
    """
    if uci.get('openvpn', instance, 'ns_inter_server', default='0') != '1':
        return False
    return uci.get('openvpn', instance, 'dev_type', default='tun') == 'tun'


def get_inter_server_routes(uci, instance):
    """
    Return the push options added to an instance by sync_inter_server_traffic().

    Arguments:
      - uci -- EUci instance
      - instance -- OpenVPN instance name

    Returns:
      - a list of push options, like 'route 10.20.0.0 255.255.255.0'
    """
    return _as_list(uci.get('openvpn', instance, 'ns_inter_server_route', list=True, default=None))


def get_inter_server_rule(instance):
    """
    Return the name of the firewall rule accepting the traffic from an instance to the other instances.

    Arguments:
      - instance -- OpenVPN instance name

    Returns:
      - the firewall section name
    """
    return f"{instance}_inter_server"


def sync_inter_server_traffic(uci):
    """
    Apply the ns_inter_server option of all the Road Warrior instances: update the routes pushed
    to the clients and the firewall rules. Call it after changing the option, the network or the
    device type of an instance, and after removing an instance.
    The changes are saved, not committed.

    Arguments:
      - uci -- EUci instance

    Returns:
      - the list of instances whose pushed routes changed: their clients get the new routes when they reconnect
    """
    instances = list_roadwarrior_instances(uci)
    networks = {}
    for instance in instances:
        if is_inter_server_enabled(uci, instance):
            network = get_instance_network(uci, instance)
            if network:
                networks[instance] = network

    changed = []
    for instance in instances:
        others = [n for i, n in networks.items() if i != instance] if instance in networks else []

        managed = get_inter_server_routes(uci, instance)
        current = _as_list(uci.get('openvpn', instance, 'push', list=True, default=None))
        routes = [f"route {n.network_address} {n.netmask}" for n in others]
        push = [p for p in current if p not in managed] + routes
        if push != current:
            changed.append(instance)
            if push:
                uci.set('openvpn', instance, 'push', push)
            else:
                _delete(uci, 'openvpn', instance, 'push')
        if routes:
            _set_if_changed(uci, 'openvpn', instance, 'ns_inter_server_route', routes)
        elif managed:
            _delete(uci, 'openvpn', instance, 'ns_inter_server_route')

        rule = get_inter_server_rule(instance)
        if others:
            _set_instance_rule(uci, rule, instance, 'inter-server', networks[instance], others)
        elif uci.get('firewall', rule, default=None) is not None:
            uci.delete('firewall', rule)

    uci.save('openvpn')
    uci.save('firewall')
    return changed


def _set_instance_rule(uci, rule, instance, suffix, network, destinations):
    # create or update a firewall rule accepting the traffic from the network of an instance
    number = re.search(r"\d+$", instance)
    if uci.get('firewall', rule, default=None) is None:
        uci.set('firewall', rule, 'rule')
    _set_if_changed(uci, 'firewall', rule, 'name', f"Allow-OpenVPNRW{number.group() if number else ''}-{suffix}")
    _set_if_changed(uci, 'firewall', rule, 'src', INTER_SERVER_ZONE)
    _set_if_changed(uci, 'firewall', rule, 'dest', INTER_SERVER_ZONE)
    _set_if_changed(uci, 'firewall', rule, 'src_ip', [str(network)])
    _set_if_changed(uci, 'firewall', rule, 'dest_ip', [str(n) for n in destinations])
    _set_if_changed(uci, 'firewall', rule, 'proto', 'all')
    _set_if_changed(uci, 'firewall', rule, 'target', 'ACCEPT')
    _set_if_changed(uci, 'firewall', rule, 'enabled', '1')
    _set_if_changed(uci, 'firewall', rule, 'ns_tag', ['automated'])
    _set_if_changed(uci, 'firewall', rule, 'ns_link', f"openvpn/{instance}")


def get_client_to_client_rule(instance):
    """
    Return the name of the firewall rule accepting the traffic between the clients of an instance.

    Arguments:
      - instance -- OpenVPN instance name

    Returns:
      - the firewall section name
    """
    return f"{instance}_client_to_client"


def sync_client_to_client_traffic(uci):
    """
    Create the firewall rules for the client_to_client option of the Road Warrior instances.
    With data channel offload (DCO) the kernel module, not OpenVPN, forwards the traffic between
    two clients of the same instance: it goes through the firewall, where the rwopenvpn zone rejects it.
    Without DCO the rules are not used. Bridged (tap) instances don't use DCO and get no rule.
    Call it after changing the option, the network or the device type of an instance.
    The changes are saved, not committed.

    Arguments:
      - uci -- EUci instance

    Returns:
      - the list of instances whose rule was created, changed or removed
    """
    changed = []
    for instance in list_roadwarrior_instances(uci):
        rule = get_client_to_client_rule(instance)
        exists = uci.get('firewall', rule, default=None) is not None
        network = None
        if uci.get('openvpn', instance, 'client_to_client', default='0') == '1' and \
                uci.get('openvpn', instance, 'dev_type', default='tun') == 'tun':
            network = get_instance_network(uci, instance)
        if network:
            before = uci.get_all('firewall', rule) if exists else None
            _set_instance_rule(uci, rule, instance, 'client-to-client', network, [network])
            if before != uci.get_all('firewall', rule):
                changed.append(instance)
        elif exists:
            uci.delete('firewall', rule)
            changed.append(instance)

    uci.save('firewall')
    return changed


def get_reserved_ip(uci, user, instance):
    """
    Return the IP address reserved for a user on an instance.
    The reservation is shared between instances, but it applies only to the
    instance whose network contains the address.

    Arguments:
      - uci -- EUci instance
      - user -- user object, as returned by users.get_user_by_name
      - instance -- OpenVPN instance name

    Returns:
      - the reserved IP address, an empty string if there is no reservation for the instance
    """
    ipaddr = user.get('openvpn_ipaddr', '')
    network = get_instance_network(uci, instance)
    if not ipaddr or network is None:
        return ''
    try:
        if ipaddress.ip_address(ipaddr) in network:
            return ipaddr
    except ValueError:
        pass
    return ''


def disconnect_client(instance, username):
    """
    Disconnect a client from an instance, using the management socket.

    Arguments:
      - instance -- OpenVPN instance name
      - username -- client common name

    Returns:
      - True if the client has been disconnected, False otherwise (e.g. it was not connected)
    """
    try:
        subprocess.run(["/usr/bin/openvpn-kill", f"/var/run/openvpn_{instance}.socket", username],
                       capture_output=True, check=True)
        return True
    except Exception:
        return False


def revoke_user_certificate(instance, username):
    """
    Revoke the certificate of a user and regenerate the CRL of the instance.
    The certificate is moved out of the issued directory, so a new one can be created for the same user name.

    Arguments:
      - instance -- OpenVPN instance name
      - username -- user name, it is the certificate common name

    Returns:
      - True if the certificate has been revoked, False if the user has no certificate

    Raises:
      - ValueError if the user name is not a valid file name
      - subprocess.CalledProcessError if easyrsa fails
    """
    if not username or os.path.basename(username) != username or username.startswith('.'):
        raise ValueError(f"invalid user name: {username}")
    pki = f"/etc/openvpn/{instance}/pki"
    if not os.path.exists(f"{pki}/issued/{username}.crt"):
        return False
    env = os.environ.copy()
    env["EASYRSA_BATCH"] = "1"
    env["EASYRSA_PKI"] = pki
    env["EASYRSA_CRL_DAYS"] = "3650"
    subprocess.run(["/usr/bin/easyrsa", "revoke", username], env=env, check=True, capture_output=True)
    subprocess.run(["/usr/bin/easyrsa", "gen-crl"], env=env, check=True, capture_output=True)
    return True


def remove_user_access(uci, user):
    """
    Remove the access of a user to all the Road Warrior instances it belongs to: the user is disconnected
    and its certificates are revoked. It must be called when a user is deleted from its database,
    passing the user object read before the deletion, so the membership is still available.
    Certificates are revoked immediately, the UCI changes are not touched.

    Arguments:
      - uci -- EUci instance
      - user -- user object, as returned by users.get_user_by_name

    Returns:
      - the list of instances where the certificate could not be revoked
    """
    errors = []
    for instance in get_user_membership(uci, user)[0]:
        disconnect_client(instance, user['name'])
        try:
            revoke_user_certificate(instance, user['name'])
        except Exception:
            errors.append(instance)
    return errors


def migrate_user_memberships(uci):
    """
    Convert legacy users to explicit per-instance membership.
    The changes are not committed.

    Arguments:
      - uci -- EUci instance

    Returns:
      - the number of migrated users
    """
    migrated = 0
    users = utils.get_all_by_type(uci, 'users', 'user') or {}
    for user_id, user in users.items():
        if 'openvpn_instances' in user or 'openvpn_enabled' not in user:
            continue
        user = dict(user, id=user_id)
        instances, disabled = get_user_membership(uci, user)
        if instances:
            _save_membership(uci, user_id, instances, disabled)
            migrated += 1
    return migrated
