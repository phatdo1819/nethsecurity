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

See docs/design/wireguard_user_auth.md.
"""

import contextlib
import hashlib
import ipaddress
import json
import os
import subprocess
import syslog
import threading
import time

from nethsec import users, utils

AUTH_MODES = ("key", "key_password", "key_password_otp")
DEFAULT_PORT = 8181
DEFAULT_TIMEOUT = 28800
MIN_TIMEOUT = 300
MAX_TIMEOUT = 604800
DEFAULT_IDLE_TIMEOUT = 300
TABLE = "ns_wgauth"
RUN_DIR = "/var/run/ns-wgauth"
SESSIONS_FILE = os.path.join(RUN_DIR, "sessions.json")
LOCK_FILE = os.path.join(RUN_DIR, "lock")

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


def get_port(uci):
    """
    Return the TCP port of the login page.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - the `ns-wgauth.config.port` option, or the default port if it's missing or invalid
    """
    try:
        port = int(uci.get("ns-wgauth", "config", "port", default=DEFAULT_PORT))
    except (TypeError, ValueError):
        return DEFAULT_PORT
    return port if 1 <= port <= 65535 else DEFAULT_PORT


def get_idle_timeout(uci):
    """
    Return the seconds without a handshake after which a session ends, 0 to never end it for that reason.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - the `ns-wgauth.config.idle_timeout` option, or the default if it's missing or invalid
    """
    try:
        timeout = int(uci.get("ns-wgauth", "config", "idle_timeout", default=DEFAULT_IDLE_TIMEOUT))
    except (TypeError, ValueError):
        return DEFAULT_IDLE_TIMEOUT
    return max(timeout, 0)


def get_lock_endpoint(uci):
    """
    Check if a session ends when its peer shows up from another public IP.

    WireGuard can't tell apart two devices with the same key: a copy of the configuration used while the user is
    logged in would share the session. The public IP the peer had at login tells them apart, unless both are behind
    the same NAT. The price: a user who changes network (for example from Wi-Fi to 4G) must log in again.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - the `ns-wgauth.config.lock_endpoint` option, True if it's missing or invalid
    """
    try:
        return uci.get("ns-wgauth", "config", "lock_endpoint", dtype=bool, default=True)
    except ValueError:
        return True


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


def find_peer(uci, address):
    """
    Find the peer that can log in from an address.

    Arguments:
      - uci -- EUci pointer
      - address -- IPv4 address of the client inside the VPN

    Returns:
      - a `(server, peer)` tuple for the enabled peer of an enabled gated server whose reserved IP is
        `address`, `(None, None)` if there is no such peer
    """
    for server in list_gated_servers(uci):
        if not is_enabled(uci, server):
            continue
        for peer, options in list_peers(uci, server).items():
            if options.get("ns_ip") == address:
                if is_enabled(uci, peer):
                    return server, peer
                return None, None
    return None, None


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
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except (TypeError, ValueError):
        # invalid secret
        return False


def check_credentials(uci, server, peer, username, password, otp=""):
    """
    Check the credentials entered on the login page against the user linked to the peer.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name
      - peer -- peer section name
      - username -- the user name entered, it must match the linked user (case insensitive)
      - password -- the password entered
      - otp -- the OTP code entered, checked only if the server requires it

    Returns:
      - the user object if the credentials are valid, None otherwise
    """
    user = get_peer_user(uci, server, peer)
    if user is None:
        return None
    if not isinstance(username, str) or username.lower() != user.get("name", "").lower():
        return None
    shadow = user.get("password", "")
    if not shadow or not isinstance(password, str) or not password:
        return None
    try:
        if not users.check_password(password, shadow):
            return None
    except (TypeError, ValueError):
        # malformed password hash
        return None
    if requires_otp(uci, server) and not verify_otp(user.get("openvpn_2fa", ""), otp):
        return None
    return user


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


def _nft_script(script):
    try:
        process = _run(["nft", "-f", "-"], input=script)
    except OSError as error:
        raise RuntimeError(f"nft failed: {error}") from error
    if process.returncode != 0:
        raise RuntimeError(f"nft failed: {process.stderr.strip()}")


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
        for element in nft_set.get("elem", []):
            left = 0
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


def build_ruleset(servers, port):
    """
    Build the nftables script that creates or updates the table for the gated servers.

    The sets are added, not replaced: the open sessions survive. The chains are flushed and filled again.
    The chains run just before fw4: a drop or a reject is final, an accept lets fw4 apply its rules.

    Arguments:
      - servers -- the gated servers, see `list_gated_servers`
      - port -- the TCP port of the login page

    Returns:
      - the script for `nft -f`
    """
    table = f"inet {TABLE}"
    devices = ", ".join(json.dumps(server) for server in servers)
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
        f"flush chain {table} input",
        f"flush chain {table} forward",
        f"flush chain {table} unauth_input",
        # the login page is reachable only from the gated WireGuard interfaces
        f'add rule {table} input iifname != @gated iifname != "lo" tcp dport {port} drop',
    ]
    for server in servers:
        device = json.dumps(server)
        lines += [
            # WireGuard server networks are IPv4 only
            f"add rule {table} input iifname {device} meta nfproto ipv6 drop",
            f"add rule {table} input iifname {device} ip saddr != @auth_{server} jump unauth_input",
            f"add rule {table} forward iifname {device} meta nfproto ipv6 drop",
            f"add rule {table} forward iifname {device} ip saddr != @auth_{server} meta l4proto tcp reject with tcp reset",
            f"add rule {table} forward iifname {device} ip saddr != @auth_{server} reject with icmpx type admin-prohibited",
            f"add rule {table} forward oifname {device} meta nfproto ipv6 drop",
            f"add rule {table} forward oifname {device} ip daddr != @auth_{server} drop",
        ]
    lines += [
        # before the login, only the login page and ping: DNS would let a copied configuration tunnel data
        f"add rule {table} unauth_input tcp dport {port} accept",
        f"add rule {table} unauth_input icmp type echo-request accept",
        f"add rule {table} unauth_input meta l4proto tcp reject with tcp reset",
        f"add rule {table} unauth_input reject with icmpx type admin-prohibited",
    ]
    return "\n".join(lines) + "\n"


def table_matches(objects, servers):
    """
    Check that the table read from nftables has the chains and sets expected for the gated servers.

    The rules are counted, not compared: a change of the login port goes through `apply_ruleset` with
    `force` set.

    Arguments:
      - objects -- see `read_table`
      - servers -- the gated servers

    Returns:
      - True if the table looks complete
    """
    sets = {}
    rules = {"input": 0, "forward": 0, "unauth_input": 0}
    chains = set()
    for item in objects:
        if "set" in item:
            sets[item["set"].get("name")] = item["set"]
        elif "chain" in item:
            chains.add(item["chain"].get("name"))
        elif "rule" in item and item["rule"].get("chain") in rules:
            rules[item["rule"]["chain"]] += 1
    if chains != set(rules) or "gated" not in sets:
        return False
    if sorted(sets["gated"].get("elem", [])) != sorted(servers):
        return False
    if {name for name in sets if name.startswith("auth_")} != {f"auth_{server}" for server in servers}:
        return False
    count = len(servers)
    return rules == {"input": 1 + 2 * count, "forward": 5 * count, "unauth_input": 4}


def apply_ruleset(uci, force=True):
    """
    Create, update or remove the `inet ns_wgauth` table to match the configuration.

    Arguments:
      - uci -- EUci pointer
      - force -- rebuild the chains even if the table looks complete

    Returns:
      - the list of gated servers
    """
    servers = list_gated_servers(uci)
    objects = read_table()
    if not servers:
        if objects:
            _nft_script(f"delete table inet {TABLE}\n")
        return servers
    if not force and table_matches(objects, servers):
        return servers
    _nft_script(build_ruleset(servers, get_port(uci)))
    # a set can be deleted only after the rules using it, so outside the main script
    wanted = {f"auth_{server}" for server in servers}
    for item in objects:
        name = item.get("set", {}).get("name", "")
        if name.startswith("auth_") and name not in wanted:
            _run(["nft", "delete", "set", "inet", TABLE, name])
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

        os.makedirs(RUN_DIR, exist_ok=True)
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
    try:
        with open(SESSIONS_FILE) as fp:
            data = json.load(fp)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_metadata(data):
    """
    Write the session metadata, see `load_metadata`.

    Arguments:
      - data -- a dictionary `{server: {address: entry}}`
    """
    os.makedirs(RUN_DIR, exist_ok=True)
    temporary = SESSIONS_FILE + ".tmp"
    with open(temporary, "w") as fp:
        json.dump({server: entries for server, entries in data.items() if entries}, fp)
    os.replace(temporary, SESSIONS_FILE)


def _element(server, address):
    return f"inet {TABLE} auth_{server} {{ {address} }}"


def _flush_connections(address):
    # deleting the conntrack entries cuts the open connections, offloaded ones too
    _run(["conntrack", "-D", "-s", address])
    _run(["conntrack", "-D", "-d", address])


def open_session(uci, server, peer, address, user):
    """
    Let a peer through after a successful login, or restart the timer of its session.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name
      - peer -- peer section name
      - address -- reserved IP of the peer
      - user -- the user object returned by `check_credentials`

    Returns:
      - the expiration time, as a UNIX timestamp
    """
    address = str(ipaddress.IPv4Address(address))
    timeout = get_session_timeout(uci, server)
    endpoint = (read_endpoints() or {}).get(uci.get("network", peer, "public_key", default=""), "")
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
            "peer": peer,
            "user": user.get("name", ""),
            "fingerprint": user_fingerprint(uci, server, user),
            "login": now,
            "expires": now + timeout,
            "endpoint": endpoint,
        }
        save_metadata(metadata)
    log(f"login: user={user.get('name', '')} server={server} peer={peer} address={address} from={endpoint}")
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
    return existed


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


def session_problem(uci, server, address, entry, handshakes, now, idle_timeout, gated, endpoints=None):
    """
    Check if an open session must end.

    Arguments:
      - uci -- EUci pointer
      - server -- WireGuard server interface name
      - address -- reserved IP of the peer
      - entry -- the session metadata, see `load_metadata`
      - handshakes -- see `read_handshakes`, None skips the check of disconnected peers
      - now -- current UNIX timestamp
      - idle_timeout -- see `get_idle_timeout`
      - gated -- the gated servers
      - endpoints -- see `read_endpoints`, None skips the check of the public IP

    Returns:
      - the reason to end the session, None if it's still valid
    """
    if server not in gated or not is_enabled(uci, server):
        return "server_changed"
    if not isinstance(entry, dict):
        return "unknown_session"
    peer = entry.get("peer", "")
    if (
        not peer
        or uci.get("network", peer, default="") != f"wireguard_{server}"
        or not is_enabled(uci, peer)
        or uci.get("network", peer, "ns_ip", default="") != address
    ):
        return "peer_changed"
    user = get_peer_user(uci, server, peer)
    if user is None or user.get("name", "").lower() != str(entry.get("user", "")).lower():
        return "user_changed"
    if user_fingerprint(uci, server, user) != entry.get("fingerprint"):
        return "user_changed"
    public_key = uci.get("network", peer, "public_key", default="")
    if endpoints is not None and entry.get("endpoint"):
        # unknown right after an interface restart, until the peer sends again
        current = endpoints.get(public_key)
        if current and current != entry["endpoint"]:
            return "endpoint_changed"
    if handshakes is not None and idle_timeout > 0:
        # restarting the interface resets the handshakes: count from the latest one ever seen, or from the login
        latest = max(
            handshakes.get(public_key, 0),
            _timestamp(entry.get("seen")),
            _timestamp(entry.get("login")),
        )
        if now - latest > idle_timeout:
            return "disconnected"
    return None


def _timestamp(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def reconcile(uci):
    """
    End the sessions that are no longer valid and forget the expired ones.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - the list of `(server, address, reason)` of the ended sessions
    """
    ended = []
    with state_lock():
        sessions = list_sessions()
        metadata = load_metadata()
        gated = list_gated_servers(uci)
        idle_timeout = get_idle_timeout(uci)
        handshakes = read_handshakes() if idle_timeout > 0 else None
        endpoints = read_endpoints() if get_lock_endpoint(uci) else None
        now = int(time.time())
        changed = False
        for server, elements in sessions.items():
            for address in elements:
                entry = metadata.get(server, {}).get(address)
                reason = session_problem(uci, server, address, entry, handshakes, now, idle_timeout, gated, endpoints)
                if reason:
                    ended.append((server, address, reason))
                if reason == "endpoint_changed":
                    public_key = uci.get("network", entry["peer"], "public_key", default="")
                    log(
                        f"possible copy of the configuration of peer {entry['peer']}: user={entry.get('user', '')} "
                        f"logged in from {entry['endpoint']}, now {endpoints[public_key]}",
                        syslog.LOG_WARNING,
                    )
                if reason or not isinstance(entry, dict):
                    continue
                public_key = uci.get("network", entry["peer"], "public_key", default="")
                latest = (handshakes or {}).get(public_key, 0)
                if latest > _timestamp(entry.get("seen")):
                    entry["seen"] = latest
                    changed = True
                # the endpoint wasn't known at login
                if endpoints and not entry.get("endpoint") and endpoints.get(public_key):
                    entry["endpoint"] = endpoints[public_key]
                    changed = True
        if changed:
            save_metadata(metadata)
        # the nftables timeout already removed the expired sessions, only the metadata is left
        for server, entries in metadata.items():
            for address in entries:
                if address not in sessions.get(server, {}):
                    ended.append((server, address, "expired"))
        for server, address, reason in ended:
            close_session(server, address, reason)
    return ended
