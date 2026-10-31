#!/usr/bin/python3

#
# Copyright (C) 2026 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Login with the credentials of a local users database on WireGuard servers.

A WireGuard server whose `ns_auth_mode` option isn't `key` is *gated*: its peers reach only the login page on
the firewall until the user logs in with the credentials of the server's `ns_user_db`. The addresses of the
logged-in peers are kept in the `inet ns_wgauth` nftables table, one set per server, and the `ns-wgauth` daemon
adds and removes them.

The daemon works on a snapshot of the configuration, see `build_state`, taken when the configuration is applied:
changes saved but not applied yet don't reach it.

A gated server can also require device binding: a peer logs in only from the device enrolled for it, which signs
every login with a key that never leaves it, see `verify_device`.

See docs/design/wireguard_user_auth.md and docs/design/wireguard_device_binding.md.
"""

import base64
import binascii
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import struct
import subprocess
import syslog
import tempfile
import threading
import time

from nethsec import users, utils

AUTH_MODES = ("key", "key_password", "key_password_otp")
LOCK_MODES = ("strict", "roaming", "off")
DEFAULT_PORT = 8181
# before the login, web requests and DNS queries of a peer are redirected to these ports, see build_ruleset
DEFAULT_REDIRECT_PORT = 8180
DEFAULT_DNS_PORT = 8153
DNS_TTL = 1
# redirected DNS queries per second and per server, the others are rejected
DNS_RATE = 100
# bumped when the snapshot written by save_state changes: an older one is taken again
STATE_VERSION = 3
DEFAULT_TIMEOUT = 28800
MIN_TIMEOUT = 300
MAX_TIMEOUT = 604800
DEFAULT_IDLE_TIMEOUT = 300
DEFAULT_MAX_FAILURES = 5
DEFAULT_LOCKOUT_TIME = 900
# a peer failing this many times max_failures, from any IP, is locked out everywhere but at its latest login IP
PEER_FAILURE_FACTOR = 4
# seconds and endpoint changes that tell two devices sharing a key from a device changing network
COPY_WINDOW = 300
COPY_CHANGES = 3
# while both devices stay active the copy is seen again and again: one alert per hour is enough
COPY_REPORT_INTERVAL = 3600
# seconds a session stays paused while its peer sends from another public IP than at login, with lock_endpoint set to
# strict, see follow_endpoints: after that, the device that logged in isn't coming back, the session ends
PAUSE_LIMIT = 300
MAX_ALERTS = 20
ALERT_AGE = 30 * 86400
TABLE = "ns_wgauth"
RUN_DIR = "/var/run/ns-wgauth"
SESSIONS_FILE = os.path.join(RUN_DIR, "sessions.json")
STATE_FILE = os.path.join(RUN_DIR, "state.json")
BLOCKED_FILE = os.path.join(RUN_DIR, "blocked.json")
LOCK_FILE = os.path.join(RUN_DIR, "lock")
# kept across reboots and upgrades: a blocked peer must stay blocked
ALERTS_FILE = "/etc/ns-wgauth/alerts.json"
# the enrolled devices, kept like the alerts: a lost enrollment would let anyone enroll again
DEVICES_FILE = "/etc/ns-wgauth/devices.json"
# seconds a peer without a device can enroll one: from its creation, its new keys or the binding of its server
DEFAULT_ENROLL_WINDOW = 72 * 3600
MAX_ENROLL_WINDOW = 30 * 86400
# seconds a challenge of the login page can be signed, and challenges kept for each address
CHALLENGE_TTL = 60
MAX_CHALLENGES = 4
DEVICE_MESSAGE = "ns-wgauth-device-v1"
DEVICE_KINDS = ("software", "tpm", "secure-enclave")
# DER SubjectPublicKeyInfo of a P-256 public key, before its 65 bytes uncompressed point
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
# a DER ECDSA P-256 signature is at most 72 bytes
MAX_SIGNATURE = 72

_lock = threading.RLock()
_lock_depth = 0


def get_auth_mode(uci, server):
    """
    Return the authentication mode of a WireGuard server.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - the `ns_auth_mode` option, `key` when it's missing
    """
    return uci.get("network", server, "ns_auth_mode", default="key") or "key"


def is_server(uci, section):
    """
    Check if a network section is a WireGuard server.

    Arguments:
      - uci -- EUci pointer
      - section -- network section name

    Returns:
      - True for a WireGuard interface with `ns_type` `server`
    """
    return (
        uci.get("network", section, "proto", default="") == "wireguard"
        and uci.get("network", section, "ns_type", default="") == "server"
    )


def is_gated(uci, server):
    """
    Check if the peers of a WireGuard server must log in.

    Every mode other than `key` requires the login, an unknown value too: a typo must not open the gate.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - True if the server requires the login
    """
    return is_server(uci, server) and get_auth_mode(uci, server) != "key"


def requires_otp(uci, server):
    """
    Check if the login of a WireGuard server requires an OTP code.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - True if the mode is `key_password_otp`
    """
    return get_auth_mode(uci, server) == "key_password_otp"


def requires_device(uci, server):
    """
    Check if the peers of a WireGuard server must log in from the device enrolled for them.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - True if the server requires the login and its `ns_device_binding` option is set
    """
    try:
        binding = uci.get("network", server, "ns_device_binding", dtype=bool, default=False)
    except ValueError:
        # a typo must not open the gate
        binding = True
    return is_gated(uci, server) and binding


def requires_machine_id(uci, server):
    """
    Check if the enrolled device of a peer must also send the ID of its machine.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - True if the server requires device binding and its `ns_machine_id` option is set
    """
    try:
        machine_id = uci.get("network", server, "ns_machine_id", dtype=bool, default=False)
    except ValueError:
        machine_id = True
    return requires_device(uci, server) and machine_id


def get_server_public_key(uci, server):
    """
    Return the WireGuard public key of a server.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - the base64 public key, empty if it can't be computed
    """
    private_key = uci.get("network", server, "private_key", default="")
    if not private_key:
        return ""
    try:
        process = _run(["wg", "pubkey"], input=private_key)
    except OSError:
        return ""
    return process.stdout.strip() if process.returncode == 0 else ""


def is_enabled(uci, section):
    """
    Check if a network section (server or peer) is enabled.

    Arguments:
      - uci -- EUci pointer
      - section -- network section name

    Returns:
      - False if the `disabled` option is set
    """
    return not uci.get("network", section, "disabled", dtype=bool, default=False)


def list_gated_servers(uci):
    """
    List the WireGuard servers that require the login, enabled or not.

    The configuration errors are not caught: an empty list would remove the gate of every server.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - a sorted list of interface names
    """
    return sorted(section for section in uci.get("network") if is_gated(uci, section))


def _get_count(uci, option, default, minimum=1):
    try:
        value = int(uci.get("ns-wgauth", "config", option, default=default))
    except (TypeError, ValueError):
        return default
    return max(value, minimum)


def _get_flag(uci, option, default):
    try:
        return uci.get("ns-wgauth", "config", option, dtype=bool, default=default)
    except ValueError:
        return default


def _get_port(uci, option, default):
    port = _get_count(uci, option, default)
    return port if port <= 65535 else default


def get_port(uci):
    """
    Return the TCP port of the login page.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - the `ns-wgauth.config.port` option, or the default port if it's missing or invalid
    """
    return _get_port(uci, "port", DEFAULT_PORT)


def get_idle_timeout(uci):
    """
    Return the seconds without a handshake after which a session ends, 0 to never end it for that reason.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - the `ns-wgauth.config.idle_timeout` option, or the default if it's missing or invalid
    """
    return _get_count(uci, "idle_timeout", DEFAULT_IDLE_TIMEOUT, minimum=0)


def get_lock_endpoint(uci):
    """
    Return what happens to a session when its peer shows up from another public IP.

    WireGuard can't tell apart two devices with the same key: a copy of the configuration used while the user is
    logged in would share the session. The public IP the peer had at login tells them apart, unless both are behind
    the same NAT.

    - `strict` (option `1`): the session ends, the user logs in again, for example after moving from Wi-Fi to 4G
    - `roaming`: the session follows the peer to its new IP. Two devices sharing the key are still caught, see
      `CopyDetector`, but a copy used while the real device is off or asleep keeps the session
    - `off` (option `0`): the IP is ignored, for a router that hides the IPs of the clients

    Arguments:
      - uci -- EUci pointer

    Returns:
      - one of `LOCK_MODES`, `strict` if the option is missing or invalid
    """
    value = str(uci.get("ns-wgauth", "config", "lock_endpoint", default="1")).lower()
    if value == "roaming":
        return "roaming"
    if value in ("0", "off", "no", "false", "disabled"):
        return "off"
    return "strict"


def get_session_timeout(uci, server):
    """
    Return the session length of a WireGuard server, in seconds.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - the `ns_auth_timeout` option within the allowed range, or the default
    """
    try:
        timeout = int(uci.get("network", server, "ns_auth_timeout", default=DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return min(max(timeout, MIN_TIMEOUT), MAX_TIMEOUT)


def get_server_address(uci, server):
    """
    Return the address of a WireGuard server inside its VPN network.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - the first address without the prefix length, None if the server has no address
    """
    addresses = uci.get("network", server, "addresses", list=True, dtype=str, default=[])
    if not addresses:
        return None
    return addresses[0].split("/")[0]


def get_login_url(uci, server):
    """
    Return the address of the login page for the peers of a WireGuard server.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - the URL, None if the server has no address
    """
    address = get_server_address(uci, server)
    if address is None:
        return None
    return f"http://{address}:{get_port(uci)}/"


def list_peers(uci, server):
    """
    List the peers of a WireGuard server.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - a dictionary of peer sections
    """
    return utils.get_all_by_type(uci, "network", f"wireguard_{server}") or {}


def peers_by_user(uci, server):
    """
    Group the peers of a server by their user. A user has one peer per server: `ns.wireguard` refuses a second one,
    this finds the ones linked before.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name

    Returns:
      - a dictionary `{user: [peer sections]}`, the user names in lowercase as the login compares them, without the
        peers that have no user
    """
    result = {}
    for peer in list_peers(uci, server):
        name = uci.get("network", peer, "ns_user", default="")
        if name:
            result.setdefault(name.lower(), []).append(peer)
    return result


def list_user_peers(uci, name, database):
    """
    List the peers linked to a user on the servers that require the login with its users database.

    The servers with the WireGuard key only don't use the link, their peers are not listed.

    Arguments:
      - uci -- EUci pointer
      - name -- user name, compared ignoring the case as the login does
      - database -- users database of the user

    Returns:
      - a list of `{"id", "name", "server", "server_name"}`: the peer section and name, the server interface and name
    """
    result = []
    for server in list_gated_servers(uci):
        if uci.get("network", server, "ns_user_db", default="") != database:
            continue
        for peer in peers_by_user(uci, server).get(name.lower(), []):
            result.append(
                {
                    "id": peer,
                    "name": uci.get("network", peer, "ns_name", default=peer),
                    "server": server,
                    "server_name": uci.get("network", server, "ns_name", default=server),
                }
            )
    return result


def remove_user_peers(uci, name, database):
    """
    Delete the peers linked to a user that is deleted, like its OpenVPN accounts: their configurations stop working,
    and a new user with the same name doesn't get them. The links to the name left on the servers with the WireGuard
    key only are removed too, see `find_stale_links`. Call it once the user is deleted. The changes are saved, not
    committed.

    Arguments:
      - uci -- EUci pointer
      - name -- user name
      - database -- users database of the user

    Returns:
      - the deleted peers, see `list_user_peers`
    """
    peers = list_user_peers(uci, name, database)
    for peer in peers:
        uci.delete("network", peer["id"])
    if peers:
        uci.save("network")
    unlink_peers(uci, find_stale_links(uci, name, database))
    return peers


def user_names(uci, database=None):
    """
    Return the names of the users of a database, or of all the databases.

    Arguments:
      - uci -- EUci pointer
      - database -- users database, None for all of them

    Returns:
      - a set of user names in lowercase, as the login compares them
    """
    return {
        options.get("name", "").lower()
        for options in (utils.get_all_by_type(uci, "users", "user") or {}).values()
        if database is None or options.get("database", "") == database
    }


def find_stale_links(uci, name, database):
    """
    Find the peers still linked to a name that has no user: left by a user deleted before its peers were deleted with
    it, or by hand. A new user with that name would get them, and with them the configuration that may still be on the
    device of the old one.

    - on the servers that require the login with `database`: the peers linked to `name` if `database` has no such user
    - on the servers with the WireGuard key only, whose links wait for the login to be turned on again: the peers
      linked to `name` if no database has such a user. A link to a user with the same name in another database stays.

    Arguments:
      - uci -- EUci pointer
      - name -- user name, compared ignoring the case
      - database -- users database

    Returns:
      - a sorted list of peer sections
    """
    key = name.lower()
    in_database = key in user_names(uci, database)
    anywhere = key in user_names(uci)
    result = []
    for server in uci.get("network"):
        if not is_server(uci, server):
            continue
        if is_gated(uci, server):
            if in_database or uci.get("network", server, "ns_user_db", default="") != database:
                continue
        elif anywhere:
            continue
        result.extend(peers_by_user(uci, server).get(key, []))
    return sorted(result)


def unlink_peers(uci, peers):
    """
    Remove the user of peers: on a server that requires the login, a peer without a user can't log in until it's
    linked again. The changes are saved, not committed.

    Arguments:
      - uci -- EUci pointer
      - peers -- peer sections
    """
    for peer in peers:
        uci.delete("network", peer, "ns_user")
    if peers:
        uci.save("network")


def get_peer_user(uci, server, peer):
    """
    Return the user linked to a peer.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name
      - peer -- peer section name

    Returns:
      - the user object from the server's local users database, None if the peer has no user or the user
        doesn't exist
    """
    name = uci.get("network", peer, "ns_user", default="")
    database = uci.get("network", server, "ns_user_db", default="")
    if not name or not database or users.get_database_type(uci, database) != "local":
        return None
    return users.get_user_by_name(uci, name, database)


def user_fingerprint(uci, server, user):
    """
    Return a fingerprint of the credentials a session is opened with.

    A session ends when the fingerprint changes: a new password, a new OTP secret, another database or
    another authentication mode.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name
      - user -- user object, see `nethsec.users.get_user_by_name`

    Returns:
      - a hex digest
    """
    parts = [
        get_auth_mode(uci, server),
        uci.get("network", server, "ns_user_db", default=""),
        user.get("name", "").lower(),
        user.get("password", ""),
    ]
    if requires_otp(uci, server):
        parts.append(user.get("openvpn_2fa", ""))
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def build_state(uci):
    """
    Collect what the login service needs from the configuration.

    `ns-wgauth sync` writes it to `STATE_FILE` when the configuration is applied, and the daemon works only on it:
    a change saved but not applied yet, kept by UCI in /tmp/.uci and visible to every reader, must not open the
    gate or end sessions before the administrator applies it.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - a dictionary with the login service settings; in `servers`, the gated servers with their enabled peers by
        reserved IP, a peer without a valid user having an empty `user`; in `peer_keys`, the public key of every
        peer of every WireGuard server, to tell which enrolled devices still belong to their peer
    """
    servers = {}
    for server in list_gated_servers(uci):
        device = requires_device(uci, server)
        peers = {}
        for peer, options in list_peers(uci, server).items():
            address = options.get("ns_ip", "")
            if not address or not is_enabled(uci, peer):
                continue
            entry = {
                "peer": peer,
                "public_key": options.get("public_key", ""),
                "user": "",
                "password": "",
                "otp_secret": "",
                "fingerprint": "",
            }
            user = get_peer_user(uci, server, peer)
            if user is not None:
                entry.update(
                    user=user.get("name", ""),
                    password=user.get("password", ""),
                    otp_secret=user.get("openvpn_2fa", ""),
                    fingerprint=user_fingerprint(uci, server, user),
                )
            peers[address] = entry
        servers[server] = {
            "name": uci.get("network", server, "ns_name", default=server),
            "enabled": is_enabled(uci, server),
            "address": get_server_address(uci, server),
            "otp": requires_otp(uci, server),
            "timeout": get_session_timeout(uci, server),
            "database": uci.get("network", server, "ns_user_db", default=""),
            "device_binding": device,
            "machine_id": requires_machine_id(uci, server),
            # signed by the devices, see device_message
            "public_key": get_server_public_key(uci, server) if device else "",
            "peers": peers,
        }
    peer_keys = {}
    for server in uci.get("network"):
        if is_server(uci, server):
            for peer, options in list_peers(uci, server).items():
                peer_keys[peer] = options.get("public_key", "")
    return {
        "version": STATE_VERSION,
        "port": get_port(uci),
        "redirect": _get_flag(uci, "redirect", True),
        "redirect_port": _get_port(uci, "redirect_port", DEFAULT_REDIRECT_PORT),
        "dns_port": _get_port(uci, "dns_port", DEFAULT_DNS_PORT),
        "idle_timeout": get_idle_timeout(uci),
        "lock_endpoint": get_lock_endpoint(uci),
        "detect_copies": _get_flag(uci, "detect_copies", True),
        "block_copies": _get_flag(uci, "block_copies", False),
        "max_failures": _get_count(uci, "max_failures", DEFAULT_MAX_FAILURES),
        "lockout_time": _get_count(uci, "lockout_time", DEFAULT_LOCKOUT_TIME),
        "enroll_window": min(_get_count(uci, "enroll_window", DEFAULT_ENROLL_WINDOW), MAX_ENROLL_WINDOW),
        "servers": servers,
        "peer_keys": peer_keys,
    }


def _read_json(path, default):
    try:
        with open(path) as fp:
            return json.load(fp)
    except (OSError, ValueError):
        return default


def _write_json(path, data):
    # readable by root only: the state holds password hashes and OTP secrets
    temporary = path + ".tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fp:
        json.dump(data, fp)
    os.replace(temporary, path)


def save_state(state):
    """
    Write the configuration snapshot the daemon works on, see `build_state`.

    Arguments:
      - state -- the dictionary returned by `build_state`
    """
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    _write_json(STATE_FILE, state)


def load_state():
    """
    Read the configuration snapshot written by `save_state`.

    Returns:
      - the snapshot, None if it's missing, unreadable or written by another version
    """
    state = _read_json(STATE_FILE, None)
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        return None
    return state


def find_peer(state, address):
    """
    Find the peer that can log in from an address.

    Arguments:
      - state -- see `build_state`
      - address -- IPv4 address of the client inside the VPN

    Returns:
      - a `(server, peer)` tuple, `peer` being the entry of the enabled peer of an enabled gated server whose
        reserved IP is `address`; `(None, None)` if there is no such peer
    """
    for server, config in sorted(state["servers"].items()):
        if config["enabled"] and address in config["peers"]:
            return server, config["peers"][address]
    return None, None


def verify_otp(secret, code):
    """
    Verify a TOTP code, accepting the previous and the next 30 seconds window for clock drift.

    Arguments:
      - secret -- base32 TOTP secret
      - code -- the code entered by the user

    Returns:
      - True if the code is valid
    """
    import pyotp

    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        return False
    if not isinstance(secret, str) or not secret:
        # pyotp accepts an empty secret: its codes are the same for everyone
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except (TypeError, ValueError):
        # invalid secret
        return False


def check_login(state, server, peer, username, password, otp=""):
    """
    Check the credentials entered on the login page against the user linked to the peer.

    Arguments:
      - state -- see `build_state`
      - server -- WireGuard server interface name
      - peer -- the peer entry returned by `find_peer`
      - username -- the user name entered, it must match the linked user (case insensitive)
      - password -- the password entered
      - otp -- the OTP code entered, checked only if the server requires it

    Returns:
      - True if the credentials are valid
    """
    name = peer.get("user", "")
    if not name or not isinstance(username, str) or username.lower() != name.lower():
        return False
    shadow = peer.get("password", "")
    if not shadow or not isinstance(password, str) or not password:
        return False
    try:
        if not users.check_password(password, shadow):
            return False
    except (TypeError, ValueError):
        # malformed password hash
        return False
    return not state["servers"][server]["otp"] or verify_otp(peer.get("otp_secret", ""), otp)


def otp_missing(state, server, peer):
    """
    Tell if the server requires an OTP code and the user linked to the peer has no OTP secret, for example after
    the removal of its OpenVPN account: nobody can log in until an administrator saves the peer again, which
    creates a new secret.

    Arguments:
      - state -- see `build_state`
      - server -- WireGuard server interface name
      - peer -- the peer entry returned by `find_peer`

    Returns:
      - True if the OTP secret is missing
    """
    return bool(state["servers"][server]["otp"] and peer.get("user") and not peer.get("otp_secret"))


def ensure_otp_secret(uci, user):
    """
    Create the TOTP secret of a user if it's missing. The secret is the `openvpn_2fa` option, shared with
    OpenVPN Road Warrior. Changes are saved to the staging area.

    Arguments:
      - uci -- EUci pointer
      - user -- user object, see `nethsec.users.get_user_by_name`

    Returns:
      - True if a secret has been created
    """
    import pyotp

    if user.get("openvpn_2fa"):
        return False
    uci.set("users", user["id"], "openvpn_2fa", pyotp.random_base32())
    uci.save("users")
    return True


def log(message, priority=syslog.LOG_INFO):
    """
    Write a message to syslog with the `ns-wgauth` tag.

    Arguments:
      - message -- text to log
      - priority -- syslog priority
    """
    syslog.openlog("ns-wgauth", syslog.LOG_PID, syslog.LOG_DAEMON)
    syslog.syslog(priority, message)


def _run(cmd, input=None):
    return subprocess.run(cmd, check=False, input=input, capture_output=True, text=True)


def _nft_script(script, check=False):
    try:
        process = _run(["nft", "-c", "-f", "-"] if check else ["nft", "-f", "-"], input=script)
    except OSError as error:
        raise RuntimeError(f"nft failed: {error}") from error
    if process.returncode != 0:
        raise RuntimeError(f"nft failed: {process.stderr.strip()}")


def check_script(script):
    """
    Ask nftables if it would accept a script, without changing anything.

    Arguments:
      - script -- see `build_ruleset`

    Returns:
      - None if the script is valid, the error otherwise
    """
    try:
        _nft_script(script, check=True)
    except RuntimeError as error:
        return str(error)
    return None


def read_table():
    """
    Read the `inet ns_wgauth` nftables table.

    Returns:
      - the list of objects of `nft -j list table`, empty if the table doesn't exist
    """
    try:
        process = _run(["nft", "-j", "list", "table", "inet", TABLE])
    except OSError:
        return []
    if process.returncode != 0:
        return []
    try:
        return json.loads(process.stdout).get("nftables", [])
    except ValueError:
        return []


def parse_sessions(objects):
    """
    Extract the open sessions from the objects of the table.

    Arguments:
      - objects -- see `read_table`

    Returns:
      - a dictionary `{server: {address: seconds_left}}`
    """
    sessions = {}
    for item in objects:
        nft_set = item.get("set")
        if not nft_set or not nft_set.get("name", "").startswith("auth_"):
            continue
        elements = {}
        for item_element in nft_set.get("elem", []):
            element, left = item_element, 0
            if isinstance(element, dict):
                element = element.get("elem", {})
                left = element.get("expires", element.get("timeout", 0))
                element = element.get("val")
            if isinstance(element, str):
                elements[element] = int(left)
        sessions[nft_set["name"][len("auth_") :]] = elements
    return sessions


def list_sessions():
    """
    List the open sessions.

    Returns:
      - a dictionary `{server: {address: seconds_left}}`
    """
    return parse_sessions(read_table())


def gate_status():
    """
    Tell what the firewall enforces.

    Returns:
      - a dictionary with `sessions`, see `list_sessions`, and `blocked`, the servers whose VPN is blocked
        because the login rules couldn't be loaded
    """
    blocked = _read_json(BLOCKED_FILE, {})
    servers = blocked.get("servers", []) if isinstance(blocked, dict) else []
    return {"sessions": list_sessions(), "blocked": sorted(servers)}


def build_ruleset(servers, port, redirect=None):
    """
    Build the nftables script that creates or updates the table for the gated servers.

    The sets are added, not replaced: the open sessions survive. The chains are flushed and filled again.
    The chains run just before fw4: a drop or a reject is final, an accept lets fw4 apply its rules.

    With `redirect`, the peers that aren't logged in find the login page from any plain http:// address: their web
    requests go to a port where nginx answers with a redirect, their DNS queries to the daemon, that answers every
    name with the address of the server, see `dns_answer`. Nothing is forwarded, so DNS still can't carry data out.

    Arguments:
      - servers -- the gated servers, see `list_gated_servers`
      - port -- the TCP port of the login page
      - redirect -- None, or the `(http_port, dns_port)` the requests are redirected to

    Returns:
      - the script for `nft -f`
    """
    table = f"inet {TABLE}"
    devices = ", ".join(json.dumps(server) for server in servers)
    tcp_ports = str(port) if redirect is None else f"{{ {port}, {redirect[0]} }}"
    lines = [
        f"add table {table}",
        f"add set {table} gated {{ type ifname; }}",
        f"flush set {table} gated",
        f"add element {table} gated {{ {devices} }}",
    ]
    for server in servers:
        lines.append(f"add set {table} auth_{server} {{ type ipv4_addr; flags timeout; }}")
    lines += [
        f"add chain {table} input {{ type filter hook input priority filter - 1; policy accept; }}",
        f"add chain {table} forward {{ type filter hook forward priority filter - 1; policy accept; }}",
        f"add chain {table} unauth_input",
        f"add chain {table} prerouting {{ type nat hook prerouting priority dstnat - 1; policy accept; }}",
        f"flush chain {table} input",
        f"flush chain {table} forward",
        f"flush chain {table} unauth_input",
        f"flush chain {table} prerouting",
    ]
    if redirect is None:
        lines.append(f"delete chain {table} prerouting")
    # the login page is reachable only from the gated WireGuard interfaces
    lines.append(f'add rule {table} input iifname != @gated iifname != "lo" tcp dport {tcp_ports} drop')
    if redirect is not None:
        lines.append(f'add rule {table} input iifname != @gated iifname != "lo" udp dport {redirect[1]} drop')
    for server in servers:
        device = json.dumps(server)
        unauth = f"iifname {device} ip saddr != @auth_{server}"
        lines += [
            # WireGuard server networks are IPv4 only
            f"add rule {table} input iifname {device} meta nfproto ipv6 drop",
            f"add rule {table} input {unauth} jump unauth_input",
            f"add rule {table} forward iifname {device} meta nfproto ipv6 drop",
            f"add rule {table} forward {unauth} meta l4proto tcp reject with tcp reset",
            f"add rule {table} forward {unauth} reject with icmpx type admin-prohibited",
            f"add rule {table} forward oifname {device} meta nfproto ipv6 drop",
            f"add rule {table} forward oifname {device} ip daddr != @auth_{server} drop",
        ]
        if redirect is not None:
            dns = f"limit rate {DNS_RATE}/second redirect to :{redirect[1]}"
            lines += [
                f"add rule {table} prerouting {unauth} udp dport 53 {dns}",
                f"add rule {table} prerouting {unauth} tcp dport 80 redirect to :{redirect[0]}",
            ]
    # before the login, only the login page and ping: DNS to the firewall resolver would let a copied configuration
    # tunnel data
    lines.append(f"add rule {table} unauth_input tcp dport {tcp_ports} accept")
    if redirect is not None:
        lines.append(f"add rule {table} unauth_input udp dport {redirect[1]} accept")
    lines += [
        f"add rule {table} unauth_input icmp type echo-request accept",
        f"add rule {table} unauth_input meta l4proto tcp reject with tcp reset",
        f"add rule {table} unauth_input reject with icmpx type admin-prohibited",
    ]
    return "\n".join(lines) + "\n"


def ruleset_for(state):
    """
    Build the nftables script for a configuration snapshot, see `build_ruleset`.

    Arguments:
      - state -- see `build_state`

    Returns:
      - the script for `nft -f`
    """
    redirect = (state["redirect_port"], state["dns_port"]) if state["redirect"] else None
    return build_ruleset(sorted(state["servers"]), state["port"], redirect)


def build_block_ruleset(servers):
    """
    Build the nftables script that blocks all the traffic of the gated servers, used when the login rules can't be
    loaded: nobody can log in, but nobody gets through with the key alone either.

    It replaces the whole table and uses only plain matches and a numeric priority, so it doesn't depend on the
    syntax of `build_ruleset`.

    Arguments:
      - servers -- the gated servers

    Returns:
      - the script for `nft -f`
    """
    table = f"inet {TABLE}"
    lines = [
        # adding the table first lets the delete work when it doesn't exist
        f"add table {table}",
        f"delete table {table}",
        f"add table {table}",
        f"add chain {table} input {{ type filter hook input priority -1; policy accept; }}",
        f"add chain {table} forward {{ type filter hook forward priority -1; policy accept; }}",
    ]
    for server in servers:
        device = json.dumps(server)
        lines += [
            f"add rule {table} input iifname {device} drop",
            f"add rule {table} forward iifname {device} drop",
            f"add rule {table} forward oifname {device} drop",
        ]
    return "\n".join(lines) + "\n"


def ruleset_shape(script):
    """
    Return the chains, and the number of rules in each, that a script built by `build_ruleset` leaves in the table.

    Arguments:
      - script -- see `build_ruleset`

    Returns:
      - a dictionary `{chain: rules}`
    """
    shape = {}
    for line in script.splitlines():
        words = line.split()
        if len(words) < 5 or words[2:4] != ["inet", TABLE]:
            continue
        if words[:2] == ["add", "chain"]:
            shape.setdefault(words[4], 0)
        elif words[:2] == ["delete", "chain"]:
            shape.pop(words[4], None)
        elif words[:2] == ["add", "rule"]:
            shape[words[4]] = shape.get(words[4], 0) + 1
    return shape


def table_matches(objects, servers, script):
    """
    Check that the table read from nftables has the chains and sets expected for the gated servers.

    The rules are counted, not compared: a change of the login port goes through `apply_ruleset` with
    `force` set.

    Arguments:
      - objects -- see `read_table`
      - servers -- the gated servers
      - script -- the script that builds the table, see `build_ruleset`

    Returns:
      - True if the table looks complete
    """
    sets = {}
    shape = {}
    for item in objects:
        if "set" in item:
            sets[item["set"].get("name")] = item["set"]
        elif "chain" in item:
            shape.setdefault(item["chain"].get("name"), 0)
        elif "rule" in item:
            chain = item["rule"].get("chain")
            shape[chain] = shape.get(chain, 0) + 1
    if "gated" not in sets or sorted(sets["gated"].get("elem", [])) != sorted(servers):
        return False
    if {name for name in sets if name.startswith("auth_")} != {f"auth_{server}" for server in servers}:
        return False
    return shape == ruleset_shape(script)


def _gates(objects, servers):
    # the table in place gates every server, with any port and with or without the redirect
    return any(
        table_matches(objects, servers, build_ruleset(servers, DEFAULT_PORT, redirect))
        for redirect in (None, (DEFAULT_REDIRECT_PORT, DEFAULT_DNS_PORT))
    )


def _interface(server, action):
    try:
        process = _run(["ubus", "call", "network.interface", action, json.dumps({"interface": server})])
    except OSError:
        return False
    return process.returncode == 0


def _block(servers, error):
    """Fail closed: block the gated servers, or take their interfaces down if even that fails."""
    previous = _read_json(BLOCKED_FILE, {})
    previous = previous if isinstance(previous, dict) else {}
    down = set(previous.get("down", []))
    try:
        _nft_script(build_block_ruleset(servers))
    except RuntimeError as block_error:
        if previous.get("error") != error:
            log(f"cannot block the VPN of {', '.join(servers)}, taking it down: {block_error}", syslog.LOG_ERR)
        down.update(server for server in servers if _interface(server, "down"))
    else:
        if previous.get("error") != error:
            log(f"cannot load the login rules, the VPN of {', '.join(servers)} is blocked: {error}", syslog.LOG_ERR)
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    _write_json(BLOCKED_FILE, {"servers": sorted(servers), "down": sorted(down), "error": error})


def _unblock(state):
    blocked = _read_json(BLOCKED_FILE, None)
    if blocked is None:
        return
    for server in blocked.get("down", []) if isinstance(blocked, dict) else []:
        # it was enabled when taken down: only a server disabled since stays down
        if state["servers"].get(server, {}).get("enabled", True):
            _interface(server, "up")
    os.remove(BLOCKED_FILE)
    log("the login rules are loaded, the VPN is no longer blocked")


def apply_ruleset(state, force=True):
    """
    Create, update or remove the `inet ns_wgauth` table to match the configuration.

    If nftables refuses the login rules and the table in place doesn't gate every server, the servers are blocked
    instead, see `build_block_ruleset`. The error is raised either way.

    Arguments:
      - state -- see `build_state`
      - force -- rebuild the chains even if the table looks complete

    Returns:
      - the list of gated servers
    """
    servers = sorted(state["servers"])
    objects = read_table()
    if not servers:
        if objects:
            _nft_script(f"delete table inet {TABLE}\n")
        _unblock(state)
        return servers
    script = ruleset_for(state)
    if not force and table_matches(objects, servers, script):
        return servers
    try:
        _nft_script(script)
    except RuntimeError as error:
        # the rules already in place, for example with the previous port, still gate every server
        if not _gates(objects, servers):
            _block(servers, str(error))
        raise
    # a set can be deleted only after the rules using it, so outside the main script
    wanted = {f"auth_{server}" for server in servers}
    for item in objects:
        name = item.get("set", {}).get("name", "")
        if name.startswith("auth_") and name not in wanted:
            _run(["nft", "delete", "set", "inet", TABLE, name])
    _unblock(state)
    return servers


@contextlib.contextmanager
def state_lock():
    """
    Serialize the changes to the sessions between threads and between processes.
    """
    global _lock_depth
    with _lock:
        if _lock_depth > 0:
            _lock_depth += 1
            try:
                yield
            finally:
                _lock_depth -= 1
            return
        import fcntl

        os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
        with open(LOCK_FILE, "a") as fp:
            fcntl.flock(fp, fcntl.LOCK_EX)
            _lock_depth = 1
            try:
                yield
            finally:
                _lock_depth = 0


def load_metadata():
    """
    Read what the firewall knows about the open sessions: peer, user and credentials fingerprint.

    Returns:
      - a dictionary `{server: {address: entry}}`
    """
    data = _read_json(SESSIONS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_metadata(data):
    """
    Write the session metadata, see `load_metadata`.

    Arguments:
      - data -- a dictionary `{server: {address: entry}}`
    """
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    _write_json(SESSIONS_FILE, {server: entries for server, entries in data.items() if entries})


def _element(server, address):
    return f"inet {TABLE} auth_{server} {{ {address} }}"


def _flush_connections(address):
    # deleting the conntrack entries cuts the open connections, offloaded ones too
    _run(["conntrack", "-D", "-s", address])
    _run(["conntrack", "-D", "-d", address])


def _flush_redirected(address):
    # conntrack keeps the redirect of a flow: after the login, the DNS queries and web requests of the peer must
    # reach their real destination
    _run(["conntrack", "-D", "-s", address, "-p", "udp", "--dport", "53"])
    _run(["conntrack", "-D", "-s", address, "-p", "tcp", "--dport", "80"])


def open_session(state, server, address, peer, endpoint=""):
    """
    Let a peer through after a successful login, or restart the timer of its session.

    Arguments:
      - state -- see `build_state`
      - server -- WireGuard server interface name
      - address -- reserved IP of the peer
      - peer -- the peer entry returned by `find_peer`
      - endpoint -- public IP the peer sends from, see `read_endpoints`

    Returns:
      - the expiration time, as a UNIX timestamp
    """
    address = str(ipaddress.IPv4Address(address))
    timeout = state["servers"][server]["timeout"]
    now = int(time.time())
    with state_lock():
        # adding an element before deleting it can't fail if it's missing
        _nft_script(
            f"add element {_element(server, address)}\n"
            f"delete element {_element(server, address)}\n"
            f"add element inet {TABLE} auth_{server} {{ {address} timeout {timeout}s }}\n"
        )
        metadata = load_metadata()
        metadata.setdefault(server, {})[address] = {
            "peer": peer["peer"],
            "public_key": peer["public_key"],
            "user": peer["user"],
            "fingerprint": peer["fingerprint"],
            "login": now,
            "expires": now + timeout,
            "endpoint": endpoint,
        }
        save_metadata(metadata)
    _flush_redirected(address)
    log(f"login: user={peer['user']} server={server} peer={peer['peer']} address={address} from={endpoint}")
    return now + timeout


def close_session(server, address, reason):
    """
    End a session: the peer is blocked again and its open connections are cut.

    Arguments:
      - server -- WireGuard server interface name
      - address -- reserved IP of the peer
      - reason -- why the session ends, written to the log

    Returns:
      - True if there was a session
    """
    address = str(ipaddress.IPv4Address(address))
    with state_lock():
        existed = address in list_sessions().get(server, {})
        if existed:
            _nft_script(f"add element {_element(server, address)}\ndelete element {_element(server, address)}\n")
        metadata = load_metadata()
        entry = metadata.get(server, {}).pop(address, None)
        save_metadata(metadata)
    if existed or entry is not None:
        _flush_connections(address)
        user = entry.get("user", "") if isinstance(entry, dict) else ""
        log(f"logout: user={user} server={server} address={address} reason={reason}")
    return existed or is_paused(entry)


def is_paused(entry):
    """
    Tell if a session is paused, see `follow_endpoints`: it has no element in the table, only its metadata.

    Arguments:
      - entry -- the session metadata, see `load_metadata`

    Returns:
      - True if the session is paused
    """
    return isinstance(entry, dict) and _timestamp(entry.get("paused")) > 0


def read_handshakes():
    """
    Read the latest handshake of every WireGuard peer.

    Returns:
      - a dictionary `{public_key: timestamp}`, None if `wg` can't be run
    """
    try:
        process = _run(["wg", "show", "all", "latest-handshakes"])
    except OSError:
        return None
    if process.returncode != 0:
        return None
    handshakes = {}
    for line in process.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[2].isdigit():
            handshakes[fields[1]] = int(fields[2])
    return handshakes


def endpoint_address(endpoint):
    """
    Return the IP of a WireGuard endpoint.

    Arguments:
      - endpoint -- `1.2.3.4:51820` or `[2001:db8::1]:51820`

    Returns:
      - the IP without the port: the NAT of a network can change the port, not the IP
    """
    if endpoint.startswith("["):
        return endpoint[1 : endpoint.find("]")]
    return endpoint.rsplit(":", 1)[0]


def read_endpoints():
    """
    Read the public IP every WireGuard peer is sending from.

    Returns:
      - a dictionary `{public_key: ip}` of the peers with a known endpoint, None if `wg` can't be run
    """
    try:
        process = _run(["wg", "show", "all", "endpoints"])
    except OSError:
        return None
    if process.returncode != 0:
        return None
    endpoints = {}
    for line in process.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and fields[2] != "(none)":
            endpoints[fields[1]] = endpoint_address(fields[2])
    return endpoints


def dns_answer(query, address, ttl=DNS_TTL):
    """
    Answer a DNS query redirected from a peer that isn't logged in: every name resolves to the server address, so
    any plain http:// address leads to the login page. Nothing is forwarded.

    Arguments:
      - query -- the DNS message received
      - address -- the IPv4 address of the server inside the VPN
      - ttl -- seconds the answer can be cached: after the login the real names must work at once

    Returns:
      - the response, with an A record for A queries and no record for the other types, None if `query` isn't a
        standard query with one question
    """
    if len(query) < 12:
        return None
    ident, flags, questions = struct.unpack("!HHH", query[:6])
    # a response, or not a standard query
    if flags & 0x8000 or (flags >> 11) & 0xF or questions != 1:
        return None
    offset = 12
    while True:
        if offset >= len(query):
            return None
        length = query[offset]
        offset += 1
        if length == 0:
            break
        # a question has no compressed names
        if length & 0xC0:
            return None
        offset += length
    if offset + 4 > len(query):
        return None
    qtype, qclass = struct.unpack("!HH", query[offset : offset + 4])
    question = query[12 : offset + 4]
    answers = b""
    if qtype == 1 and qclass == 1:
        answers = struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + ipaddress.IPv4Address(address).packed
    # response, authoritative, recursion desired copied from the query, recursion available
    reply_flags = 0x8000 | 0x0400 | (flags & 0x0100) | 0x0080
    return struct.pack("!HHHHHH", ident, reply_flags, 1, 1 if answers else 0, 0, 0) + question + answers


def load_alerts():
    """
    Read the alerts of the peers: suspected copies of their configuration and lockouts.

    Returns:
      - a dictionary `{peer: {"public_key": key, "blocked": bool, "events": [event]}}`, every event being
        `{"time": timestamp, "type": "copy", "lockout" or "device_mismatch", "user": name, "addresses": [ip]}`
    """
    data = _read_json(ALERTS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_alerts(alerts):
    """
    Write the alerts, see `load_alerts`.

    Arguments:
      - alerts -- the dictionary returned by `load_alerts`
    """
    os.makedirs(os.path.dirname(ALERTS_FILE), mode=0o700, exist_ok=True)
    _write_json(ALERTS_FILE, alerts)


def peer_alerts(alerts, peer, public_key):
    """
    Return the alerts of a peer.

    The alerts belong to the keys of the peer: once new keys are generated, the old ones, and the copies made of
    them, don't matter anymore.

    Arguments:
      - alerts -- see `load_alerts`
      - peer -- peer section name
      - public_key -- the current public key of the peer

    Returns:
      - the alert entry, None if the peer has none for its current keys
    """
    entry = alerts.get(peer)
    if isinstance(entry, dict) and public_key and entry.get("public_key") == public_key:
        return entry
    return None


def is_blocked(peer, alerts=None):
    """
    Check if a peer is blocked after a suspected copy of its configuration.

    Arguments:
      - peer -- the peer entry returned by `find_peer`
      - alerts -- see `load_alerts`, read from the file if missing

    Returns:
      - True if the peer is blocked
    """
    alerts = load_alerts() if alerts is None else alerts
    entry = peer_alerts(alerts, peer["peer"], peer["public_key"])
    return bool(entry and entry.get("blocked"))


def add_alert(peer, public_key, kind, user, addresses, block=False):
    """
    Record an alert for a peer, written to `ALERTS_FILE`.

    Arguments:
      - peer -- peer section name
      - public_key -- the current public key of the peer
      - kind -- `copy`, `lockout` or `device_mismatch`
      - user -- the user linked to the peer
      - addresses -- the public IPs involved
      - block -- block the peer until an administrator clears its alerts or generates new keys
    """
    now = int(time.time())
    with state_lock():
        alerts = load_alerts()
        entry = peer_alerts(alerts, peer, public_key) or {"public_key": public_key, "blocked": False, "events": []}
        events = [
            event
            for event in entry.get("events", [])
            if isinstance(event, dict) and now - _timestamp(event.get("time")) < ALERT_AGE
        ]
        events.append({"time": now, "type": kind, "user": user, "addresses": [ip for ip in addresses if ip]})
        entry["events"] = events[-MAX_ALERTS:]
        entry["blocked"] = bool(entry.get("blocked")) or block
        alerts[peer] = entry
        save_alerts(alerts)


def clear_alerts(peer):
    """
    Forget the alerts of a peer, and unblock it.

    Arguments:
      - peer -- peer section name

    Returns:
      - True if the peer had alerts
    """
    with state_lock():
        alerts = load_alerts()
        if alerts.pop(peer, None) is None:
            return False
        save_alerts(alerts)
    log(f"alerts cleared: peer={peer}")
    return True


def prune_alerts(uci):
    """
    Forget the alerts of the peers removed, or whose keys were generated again.

    Arguments:
      - uci -- EUci pointer
    """
    with state_lock():
        alerts = load_alerts()
        kept = {
            peer: entry
            for peer, entry in alerts.items()
            if isinstance(entry, dict)
            and entry.get("public_key")
            and uci.get("network", peer, "public_key", default="") == entry["public_key"]
        }
        if kept != alerts:
            save_alerts(kept)


def load_devices():
    """
    Read the devices of the peers, see `verify_device`.

    Returns:
      - a dictionary `{peer: {"public_key": key, "window_until": timestamp, "device": device}}`: `public_key` is the
        WireGuard key of the peer the entry belongs to, `window_until` the end of its enrollment window, 0 when
        closed, `device` None or `{"key": base64 public key, "kind": kind, "name": name, "machine_id": hmac,
        "enrolled": timestamp, "last_used": timestamp, "endpoint": ip}`
    """
    data = _read_json(DEVICES_FILE, {})
    return data if isinstance(data, dict) else {}


def save_devices(devices):
    """
    Write the devices, see `load_devices`.

    Arguments:
      - devices -- the dictionary returned by `load_devices`
    """
    os.makedirs(os.path.dirname(DEVICES_FILE), mode=0o700, exist_ok=True)
    _write_json(DEVICES_FILE, devices)


def peer_device(devices, peer, public_key):
    """
    Return the device entry of a peer.

    The entry belongs to the keys of the peer, like the alerts: new keys need a new enrollment.

    Arguments:
      - devices -- see `load_devices`
      - peer -- peer section name
      - public_key -- the current public key of the peer

    Returns:
      - the entry, None if the peer has none for its current keys
    """
    entry = devices.get(peer)
    if isinstance(entry, dict) and public_key and entry.get("public_key") == public_key:
        return entry
    return None


def device_state(entry, now=None):
    """
    Tell if a peer has a device.

    Arguments:
      - entry -- see `peer_device`
      - now -- current UNIX timestamp

    Returns:
      - `enrolled`, `waiting` if a device can enroll, `closed` if none can
    """
    now = int(time.time()) if now is None else now
    if not entry:
        return "closed"
    if isinstance(entry.get("device"), dict):
        return "enrolled"
    return "waiting" if _timestamp(entry.get("window_until")) > now else "closed"


def sync_devices(state, now=None):
    """
    Match the devices with the configuration applied: forget the entries of the peers removed or given new keys,
    and open the enrollment window of the peers of the servers that require device binding and have no entry yet:
    new peers, new keys, or a server whose binding was just turned on.

    Arguments:
      - state -- see `build_state`
      - now -- current UNIX timestamp

    Returns:
      - the devices, see `load_devices`
    """
    now = int(time.time()) if now is None else now
    keys = state.get("peer_keys", {})
    with state_lock():
        devices = load_devices()
        kept = {
            peer: entry
            for peer, entry in devices.items()
            if isinstance(entry, dict) and entry.get("public_key") and keys.get(peer) == entry["public_key"]
        }
        for server, config in sorted(state["servers"].items()):
            if not config.get("device_binding"):
                continue
            for peer in config["peers"].values():
                if not peer["public_key"] or peer["peer"] in kept:
                    continue
                kept[peer["peer"]] = {
                    "public_key": peer["public_key"],
                    "window_until": now + state["enroll_window"],
                    "device": None,
                }
                log(f"device enrollment open: peer={peer['peer']} server={server} for {state['enroll_window']} seconds")
        if kept != devices:
            save_devices(kept)
    return kept


def allow_enrollment(peer, public_key, seconds=DEFAULT_ENROLL_WINDOW):
    """
    Forget the device of a peer and let a new one enroll at the next login, for example after a reinstall.

    Arguments:
      - peer -- peer section name
      - public_key -- the current public key of the peer
      - seconds -- how long the enrollment stays possible

    Returns:
      - the end of the enrollment window, as a UNIX timestamp
    """
    until = int(time.time()) + min(max(int(seconds), 60), MAX_ENROLL_WINDOW)
    with state_lock():
        devices = load_devices()
        devices[peer] = {"public_key": public_key, "window_until": until, "device": None}
        save_devices(devices)
    log(f"device enrollment open: peer={peer} by the administrator")
    return until


def revoke_device(peer, public_key):
    """
    Forget the device of a peer: it can't log in until an administrator allows a new enrollment.

    Arguments:
      - peer -- peer section name
      - public_key -- the current public key of the peer

    Returns:
      - True if the peer had a device
    """
    with state_lock():
        devices = load_devices()
        entry = peer_device(devices, peer, public_key) or {}
        had_device = isinstance(entry.get("device"), dict)
        devices[peer] = {"public_key": public_key, "window_until": 0, "device": None}
        save_devices(devices)
    log(f"device revoked: peer={peer}")
    return had_device


def device_message(challenge, server_key, peer_key, address, username, machine_id=""):
    """
    Build the message a device signs to log in: it ties the signature to one challenge, one server, one peer and
    one user name.

    Arguments:
      - challenge -- see `Challenges`
      - server_key -- WireGuard public key of the server
      - peer_key -- WireGuard public key of the peer
      - address -- reserved IP of the peer
      - username -- the user name, as entered
      - machine_id -- see `verify_device`, empty when the device doesn't send it

    Returns:
      - the message, as bytes
    """
    fields = [DEVICE_MESSAGE, challenge, server_key, peer_key, address, username, machine_id]
    return "\n".join(fields).encode()


def device_key_id(key):
    """
    Return the ID of the key of a device, as the app of the device computes it: the SHA-256 of its DER public key.

    Arguments:
      - key -- base64 DER SubjectPublicKeyInfo, see `decode_public_key`

    Returns:
      - the ID, 64 lowercase hex digits, empty if `key` isn't a P-256 public key
    """
    der = decode_public_key(key)
    return hashlib.sha256(der).hexdigest() if der else ""


def decode_public_key(text):
    """
    Decode the public key of a device.

    Arguments:
      - text -- base64 DER SubjectPublicKeyInfo

    Returns:
      - the DER bytes of a P-256 public key, None if `text` isn't one
    """
    if not isinstance(text, str):
        return None
    try:
        der = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    prefix = len(P256_SPKI_PREFIX)
    if len(der) != prefix + 65 or not der.startswith(P256_SPKI_PREFIX) or der[prefix] != 4:
        return None
    return der


def _decode_signature(text):
    if not isinstance(text, str):
        return None
    try:
        signature = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    # a DER sequence of two integers
    if not 8 <= len(signature) <= MAX_SIGNATURE or signature[0] != 0x30:
        return None
    return signature


def verify_signature(public_key, message, signature):
    """
    Check an ECDSA P-256 SHA-256 signature with openssl, already in the image for nginx.

    Arguments:
      - public_key -- DER SubjectPublicKeyInfo, see `decode_public_key`
      - message -- the signed bytes
      - signature -- DER signature

    Returns:
      - True if the signature is valid
    """
    pem = "-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(public_key).decode() + "-----END PUBLIC KEY-----\n"
    paths = []
    try:
        os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
        for suffix, data in ((".pem", pem.encode()), (".sig", signature)):
            fd, path = tempfile.mkstemp(suffix=suffix, dir=RUN_DIR)
            paths.append(path)
            with os.fdopen(fd, "wb") as fp:
                fp.write(data)
        process = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", paths[0], "-signature", paths[1]],
            input=message,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        log(f"cannot check a device signature: {error}", syslog.LOG_ERR)
        return False
    finally:
        for path in paths:
            with contextlib.suppress(OSError):
                os.remove(path)
    return process.returncode == 0


def _is_line(value):
    return isinstance(value, str) and value != "" and "\n" not in value and "\r" not in value


def _is_machine_id(value):
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _device_name(value):
    if not isinstance(value, str):
        return ""
    return "".join(char for char in value if char.isprintable())[:64]


def verify_device(state, server, address, peer, username, proof, entry, now=None):
    """
    Check the device a peer logs in from.

    The device keeps a P-256 key pair that never leaves it and signs `device_message`. It can be enrolled during the
    enrollment window of the peer, then only that device can log in. With `machine_id`, the device also sends an
    HMAC-SHA256 of the ID of its machine, keyed with the server public key, recorded at enrollment and compared at
    every login. The challenge of the proof must already be checked, see `Challenges`.

    Arguments:
      - state -- see `build_state`
      - server -- WireGuard server interface name
      - address -- reserved IP of the peer
      - peer -- the peer entry returned by `find_peer`
      - username -- the user name entered
      - proof -- the `device` object of the login request: `challenge`, `signature` (base64 DER), `public_key`
        (base64 DER), `kind`, `name` and `machine_id` (hex)
      - entry -- the device entry of the peer, see `peer_device`
      - now -- current UNIX timestamp

    Returns:
      - `(None, None)` if the enrolled device signed
      - `(None, device)` if the peer can enroll a device and that device signed: `device` is the record to save
        after a successful login, see `record_device_login`
      - `(error, None)` otherwise: `device_not_enrolled` when the peer has no device and can't enroll one,
        `device_mismatch` for another device, another machine or a wrong signature
    """
    now = int(time.time()) if now is None else now
    config = state["servers"][server]
    device = entry.get("device") if entry else None
    enrolling = not isinstance(device, dict)
    if enrolling and device_state(entry, now) != "waiting":
        return "device_not_enrolled", None
    challenge = proof.get("challenge")
    machine_id = proof.get("machine_id", "")
    key = decode_public_key(proof.get("public_key"))
    signature = _decode_signature(proof.get("signature"))
    if key is None or signature is None or not _is_line(challenge) or not _is_line(username):
        return "device_mismatch", None
    if not isinstance(machine_id, str) or (machine_id and not _is_machine_id(machine_id)):
        return "device_mismatch", None
    if config["machine_id"] and not machine_id:
        return "device_mismatch", None
    if not enrolling:
        if key != decode_public_key(device.get("key")):
            return "device_mismatch", None
        recorded = device.get("machine_id", "")
        if config["machine_id"] and recorded and not hmac.compare_digest(recorded.encode(), machine_id.encode()):
            return "device_mismatch", None
    if not config["public_key"]:
        log(f"cannot check the devices of {server}: its public key is unknown", syslog.LOG_ERR)
        return "device_mismatch", None
    message = device_message(challenge, config["public_key"], peer["public_key"], address, username, machine_id)
    if not verify_signature(key, message, signature):
        return "device_mismatch", None
    if not enrolling:
        return None, None
    kind = proof.get("kind") if proof.get("kind") in DEVICE_KINDS else "software"
    return None, {
        "key": base64.b64encode(key).decode(),
        "kind": kind,
        "name": _device_name(proof.get("name")),
        "machine_id": machine_id,
    }


def record_device_login(peer, enrolled, machine_id, endpoint, now=None):
    """
    Record a successful login from a device: enroll it, or update its last use.

    Arguments:
      - peer -- the peer entry returned by `find_peer`
      - enrolled -- the device returned by `verify_device` when the peer enrolls one, None otherwise
      - machine_id -- the machine ID sent: recorded if the device has none yet, after the server started to ask
      - endpoint -- public IP of the client
      - now -- current UNIX timestamp

    Returns:
      - False if the device can't be enrolled anymore: another one enrolled at the same time, or the window closed
    """
    now = int(time.time()) if now is None else now
    with state_lock():
        devices = load_devices()
        entry = peer_device(devices, peer["peer"], peer["public_key"])
        if enrolled is not None:
            if device_state(entry, now) != "waiting":
                return False
            entry["device"] = dict(enrolled, enrolled=now, last_used=now, endpoint=endpoint)
            entry["window_until"] = 0
            log(
                f"device enrolled: peer={peer['peer']} user={peer['user']} name={enrolled['name']!r} "
                f"kind={enrolled['kind']} from={endpoint}"
            )
        elif entry is not None and isinstance(entry.get("device"), dict):
            device = entry["device"]
            device["last_used"] = now
            device["endpoint"] = endpoint
            if machine_id and not device.get("machine_id"):
                device["machine_id"] = machine_id
                log(f"machine ID recorded: peer={peer['peer']} user={peer['user']}")
        else:
            return False
        save_devices(devices)
    return True


class Challenges:
    """
    The challenges the login page gives the devices to sign, see `verify_device`: random, for one address, valid
    `CHALLENGE_TTL` seconds and for one login. A few are kept for each address, as the client can ask the status
    again while it signs.
    """

    def __init__(self, ttl=CHALLENGE_TTL, keep=MAX_CHALLENGES):
        self.lock = threading.Lock()
        self.ttl = ttl
        self.keep = keep
        # address -> [(time, challenge)]
        self.issued = {}

    def issue(self, address, now):
        """
        Give a new challenge to an address.

        Arguments:
          - address -- reserved IP of the peer
          - now -- current UNIX timestamp

        Returns:
          - the challenge, base64
        """
        challenge = base64.b64encode(os.urandom(32)).decode()
        with self.lock:
            for other in list(self.issued):
                self.issued[other] = [item for item in self.issued[other] if now - item[0] < self.ttl]
                if not self.issued[other]:
                    del self.issued[other]
            recent = self.issued.get(address, [])
            recent.append((now, challenge))
            self.issued[address] = recent[-self.keep :]
        return challenge

    def use(self, address, challenge, now):
        """
        Use a challenge: it works once, from the address it was given to, before it expires.

        Arguments:
          - address -- reserved IP of the peer
          - challenge -- the challenge sent back
          - now -- current UNIX timestamp

        Returns:
          - True if the challenge is valid
        """
        if not isinstance(challenge, str) or not challenge:
            return False
        with self.lock:
            recent = [item for item in self.issued.get(address, []) if now - item[0] < self.ttl]
            found = [item for item in recent if hmac.compare_digest(item[1].encode(), challenge.encode())]
            if found:
                recent.remove(found[0])
            self.issued[address] = recent
        return bool(found)


class CopyDetector:
    """
    Spot two devices using the same peer configuration at once.

    WireGuard sends to the public IP of the latest packet received, so while two devices with the same key are
    active the endpoint of the peer keeps switching between their IPs. A device that changes network switches
    once, or through new IPs. `observe` reports a key whose endpoint changed `COPY_CHANGES` times within
    `COPY_WINDOW` seconds, going back to an IP it already had.
    """

    def __init__(self, window=COPY_WINDOW, changes=COPY_CHANGES):
        self.window = window
        self.changes = changes
        # public key -> latest IP seen
        self.last = {}
        # public key -> [(time, previous ip, new ip)] of the changes in the window
        self.history = {}

    def observe(self, endpoints, now):
        """
        Record the current endpoints.

        Arguments:
          - endpoints -- see `read_endpoints`, limited to the peers to watch
          - now -- current UNIX timestamp

        Returns:
          - a dictionary `{public_key: [ip]}` of the keys that look used by more than one device
        """
        suspects = {}
        for public_key, address in endpoints.items():
            previous = self.last.get(public_key)
            self.last[public_key] = address
            if previous is None or previous == address:
                continue
            changes = [change for change in self.history.get(public_key, []) if now - change[0] < self.window]
            changes.append((now, previous, address))
            self.history[public_key] = changes
            seen = {changes[0][1]} | {change[2] for change in changes}
            # a return to an IP already seen: with only new IPs it's a device moving
            if len(changes) >= self.changes and len(seen) <= len(changes):
                suspects[public_key] = sorted(seen)
                self.history[public_key] = []
        for public_key in set(self.last) - set(endpoints):
            del self.last[public_key]
            self.history.pop(public_key, None)
        return suspects


class LoginFailures:
    """
    Count the failed logins of each peer by public IP of the client.

    Someone using a copy of the configuration from another network can't lock out the real user. A peer failing
    `PEER_FAILURE_FACTOR` times `max_failures` from many IPs is locked out from all of them, except the IP of its
    latest successful login, so the IPs don't multiply the attempts.
    """

    def __init__(self):
        self.lock = threading.Lock()
        # peer -> [(time, ip)] of the recent failures
        self.failures = {}
        # peer -> ip of the latest successful login
        self.trusted = {}

    def _recent(self, peer, now, lockout_time):
        recent = [failure for failure in self.failures.get(peer, []) if now - failure[0] < lockout_time]
        self.failures[peer] = recent
        return recent

    def locked_until(self, peer, endpoint, now, max_failures, lockout_time):
        """
        Check if a peer can try to log in from an IP.

        Arguments:
          - peer -- peer section name
          - endpoint -- public IP of the client, empty if unknown
          - now -- current UNIX timestamp
          - max_failures -- failures from one IP before it's locked out
          - lockout_time -- seconds a lockout lasts

        Returns:
          - the end of the lockout as a UNIX timestamp, None if the login can be tried
        """
        with self.lock:
            recent = self._recent(peer, now, lockout_time)
            own = [moment for moment, source in recent if source == endpoint]
            if len(own) >= max_failures:
                return own[-1] + lockout_time
            if endpoint != self.trusted.get(peer) and len(recent) >= max_failures * PEER_FAILURE_FACTOR:
                return recent[-1][0] + lockout_time
        return None

    def add(self, peer, endpoint, now, max_failures, lockout_time):
        """
        Record a failed login, see `locked_until` for the arguments.

        Returns:
          - the IPs locked out by this failure, empty if it locked out nothing new
        """
        with self.lock:
            recent = self._recent(peer, now, lockout_time)
            recent.append((now, endpoint))
            if sum(1 for _, source in recent if source == endpoint) == max_failures:
                return [endpoint]
            if len(recent) == max_failures * PEER_FAILURE_FACTOR:
                return sorted({source for _, source in recent})
        return []

    def success(self, peer, endpoint):
        """
        Record a successful login: the failures from its IP are forgotten, the others stay.

        Arguments:
          - peer -- peer section name
          - endpoint -- public IP of the client
        """
        with self.lock:
            self.failures[peer] = [failure for failure in self.failures.get(peer, []) if failure[1] != endpoint]
            self.trusted[peer] = endpoint


def report_copy(state, public_key, addresses):
    """
    Handle a suspected copy of a peer configuration, see `CopyDetector`: end the session of the peer, log it and
    record the alert, at most once every `COPY_REPORT_INTERVAL`, and with `block_copies` block the peer until an
    administrator clears the alert or generates new keys.

    Arguments:
      - state -- see `build_state`
      - public_key -- the public key used by more than one device
      - addresses -- the public IPs seen

    Returns:
      - the peer section name, None if the key isn't a peer of a gated server
    """
    now = int(time.time())
    for server, config in sorted(state["servers"].items()):
        for address, peer in config["peers"].items():
            if peer["public_key"] != public_key:
                continue
            block = state["block_copies"]
            entry = peer_alerts(load_alerts(), peer["peer"], public_key) or {}
            reported = any(
                isinstance(event, dict)
                and event.get("type") == "copy"
                and now - _timestamp(event.get("time")) < COPY_REPORT_INTERVAL
                for event in entry.get("events", [])
            )
            if not reported or (block and not entry.get("blocked")):
                log(
                    f"possible copy of the configuration of peer {peer['peer']}: user={peer['user']} "
                    f"used from {', '.join(addresses)} at the same time" + (", peer blocked" if block else ""),
                    syslog.LOG_WARNING,
                )
                add_alert(peer["peer"], public_key, "copy", peer["user"], addresses, block=block)
            close_session(server, address, "copy_suspected")
            return peer["peer"]
    return None


def endpoint_action(state, entry, current):
    """
    Decide what the lock of the public IP does with a session, see `follow_endpoints`.

    Arguments:
      - state -- see `build_state`
      - entry -- the session metadata, see `load_metadata`
      - current -- the public IP the peer sends from, see `read_endpoints`, None if unknown

    Returns:
      - `pause`, `resume` or None
    """
    if not isinstance(entry, dict):
        return None
    paused = is_paused(entry)
    if state["lock_endpoint"] != "strict":
        # the lock was turned off meanwhile
        return "resume" if paused else None
    if not current or not entry.get("endpoint"):
        # unknown right after an interface restart, until the peer sends again, or not recorded at login
        return None
    if current != entry["endpoint"]:
        return None if paused else "pause"
    return "resume" if paused else None


def follow_endpoints(state, endpoints, now=None, only=None):
    """
    Lock the sessions to the public IP their peer logged in from, with `lock_endpoint` set to strict.

    When the peer sends from another IP, its key is used by another device, or the device moved to another network:
    the session is paused, the peer is blocked again and its connections are cut, but the session doesn't end. It
    resumes, for the time it has left, when the peer sends from the IP of the login again: when a copy of the
    configuration goes away, the device that logged in gets its session back without a new login. A session paused
    for `PAUSE_LIMIT` seconds ends, see `session_problem`.

    Arguments:
      - state -- see `build_state`
      - endpoints -- see `read_endpoints`, None if unknown
      - now -- current UNIX timestamp
      - only -- the `(server, address)` of the one session to check

    Returns:
      - the list of `(server, address, action)`, `action` being `pause` or `resume`
    """
    now = int(time.time()) if now is None else now
    done = []
    with state_lock():
        metadata = load_metadata()
        for server, entries in sorted(metadata.items()):
            config = state["servers"].get(server)
            if config is None or not isinstance(entries, dict):
                continue
            for address, entry in sorted(entries.items()):
                if only is not None and only != (server, address):
                    continue
                peer = config["peers"].get(address)
                if peer is None or not isinstance(entry, dict) or entry.get("public_key") != peer["public_key"]:
                    # `reconcile` ends it
                    continue
                current = (endpoints or {}).get(peer["public_key"])
                action = endpoint_action(state, entry, current)
                if action == "pause":
                    _nft_script(
                        f"add element {_element(server, address)}\ndelete element {_element(server, address)}\n"
                    )
                    entry["paused"] = now
                elif action == "resume":
                    left = _timestamp(entry.get("expires")) - now
                    if left <= 0:
                        # expired meanwhile: `reconcile` ends it
                        continue
                    _nft_script(f"add element inet {TABLE} auth_{server} {{ {address} timeout {left}s }}\n")
                    entry.pop("paused", None)
                if action:
                    done.append((server, address, action, entry, current))
        if done:
            save_metadata(metadata)
    for server, address, action, entry, current in done:
        who = f"peer {entry.get('peer', '')} of user={entry.get('user', '')}"
        if action == "pause":
            _flush_connections(address)
            log(
                f"session paused: {who} sends from {current}, it logged in from {entry['endpoint']}",
                syslog.LOG_WARNING,
            )
        else:
            log(f"session resumed: {who} sends from {entry['endpoint']} again")
    return [(server, address, action) for server, address, action, _entry, _current in done]


def session_problem(state, server, address, entry, handshakes, now, blocked=()):
    """
    Check if a session must end, an open or a paused one.

    Arguments:
      - state -- see `build_state`
      - server -- WireGuard server interface name
      - address -- reserved IP of the peer
      - entry -- the session metadata, see `load_metadata`
      - handshakes -- see `read_handshakes`, None skips the check of disconnected peers
      - now -- current UNIX timestamp
      - blocked -- the peer section names that are blocked

    Returns:
      - the reason to end the session, None if it's still valid
    """
    config = state["servers"].get(server)
    if config is None or not config["enabled"]:
        return "server_changed"
    if not isinstance(entry, dict):
        return "unknown_session"
    peer = config["peers"].get(address)
    if peer is None or peer["peer"] != entry.get("peer") or peer["public_key"] != entry.get("public_key"):
        return "peer_changed"
    if not peer["user"] or peer["user"].lower() != str(entry.get("user", "")).lower():
        return "user_changed"
    if peer["fingerprint"] != entry.get("fingerprint"):
        return "user_changed"
    if peer["peer"] in blocked:
        return "blocked"
    if is_paused(entry):
        if now - _timestamp(entry["paused"]) > PAUSE_LIMIT:
            # the device that logged in didn't come back: another device kept the key, or it changed network
            return "endpoint_changed"
        # no element in the table, so no nftables timeout
        if _timestamp(entry.get("expires")) <= now:
            return "expired"
    if handshakes is not None and state["idle_timeout"] > 0:
        # restarting the interface resets the handshakes: count from the latest one ever seen, or from the login
        latest = max(
            handshakes.get(peer["public_key"], 0),
            _timestamp(entry.get("seen")),
            _timestamp(entry.get("login")),
        )
        if now - latest > state["idle_timeout"]:
            return "disconnected"
    return None


def _timestamp(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def reconcile(state):
    """
    End the sessions that are no longer valid and forget the expired ones, then pause or resume the others, see
    `follow_endpoints`.

    Arguments:
      - state -- see `build_state`

    Returns:
      - the list of `(server, address, reason)` of the ended sessions
    """
    ended = []
    with state_lock():
        sessions = list_sessions()
        metadata = load_metadata()
        handshakes = read_handshakes() if state["idle_timeout"] > 0 else None
        endpoints = read_endpoints() if state["lock_endpoint"] != "off" else None
        alerts = load_alerts()
        blocked = {
            peer["peer"]
            for config in state["servers"].values()
            for peer in config["peers"].values()
            if is_blocked(peer, alerts)
        }
        now = int(time.time())
        changed = False
        found = {(server, address) for server, elements in sessions.items() for address in elements}
        found |= {(server, address) for server, entries in metadata.items() for address in entries}
        for server, address in sorted(found):
            entry = metadata.get(server, {}).get(address)
            if address not in sessions.get(server, {}) and not is_paused(entry):
                # the nftables timeout already removed it, only the metadata is left
                ended.append((server, address, "expired"))
                continue
            reason = session_problem(state, server, address, entry, handshakes, now, blocked)
            if reason:
                ended.append((server, address, reason))
                if reason == "endpoint_changed":
                    log(
                        f"peer {entry['peer']} of user={entry.get('user', '')} didn't come back to {entry['endpoint']} "
                        f"in {PAUSE_LIMIT} seconds: the user must log in again"
                    )
                continue
            public_key = state["servers"][server]["peers"][address]["public_key"]
            latest = (handshakes or {}).get(public_key, 0)
            if latest > _timestamp(entry.get("seen")):
                entry["seen"] = latest
                changed = True
            current = (endpoints or {}).get(public_key)
            # with lock_endpoint set to strict, the IP of the login stays: follow_endpoints pauses the session
            moved = entry.get("endpoint") and state["lock_endpoint"] == "roaming"
            if current and current != entry.get("endpoint") and (moved or not entry.get("endpoint")):
                # unknown at login, or the client moved to another network
                if entry.get("endpoint"):
                    user = entry.get("user", "")
                    log(f"peer {entry['peer']} of user={user} moved from {entry['endpoint']} to {current}")
                entry["endpoint"] = current
                changed = True
        if changed:
            save_metadata(metadata)
        for server, address, reason in ended:
            close_session(server, address, reason)
        follow_endpoints(state, endpoints, now)
    return ended
