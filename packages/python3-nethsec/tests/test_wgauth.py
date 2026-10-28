import base64
import json
import os
import shutil
import struct
import subprocess
import time

import pyotp
import pytest
from euci import EUci
from nethsec import users, wgauth

OTP_SECRET = "JBSWY3DPEHPK3PXP"
PASSWORD = "Secret,1234"
ALICE = "wg1_ns_aaaaaaaa_peer"
SERVER_KEY = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

network_db = """
config interface 'lan'
	option proto 'static'

config interface 'wg1'
	option proto 'wireguard'
	option ns_type 'server'
	option ns_name 'Road warriors'
	option ns_auth_mode 'key_password'
	option ns_user_db 'wgauth_users'
	option ns_auth_timeout '3600'
	list addresses '10.103.1.1/24'

config wireguard_wg1 'wg1_ns_aaaaaaaa_peer'
	option ns_ip '10.103.1.2'
	option ns_user 'alice'
	option public_key 'KEY_ALICE'

config wireguard_wg1 'wg1_ns_bbbbbbbb_peer'
	option ns_ip '10.103.1.3'
	option ns_user 'bob'
	option disabled '1'
	option public_key 'KEY_BOB'

config wireguard_wg1 'wg1_ns_eeeeeeee_peer'
	option ns_ip '10.103.1.4'
	option public_key 'KEY_NOBODY'

config interface 'wg2'
	option proto 'wireguard'
	option ns_type 'server'
	list addresses '10.103.2.1/24'

config wireguard_wg2 'wg2_ns_cccccccc_peer'
	option ns_ip '10.103.2.2'

config interface 'wg3'
	option proto 'wireguard'
	option ns_type 'tunnel'
	option ns_auth_mode 'key_password'

config interface 'wg4'
	option proto 'wireguard'
	option ns_type 'server'
	option ns_auth_mode 'key_password_otp'
	option ns_user_db 'wgauth_users'
	option disabled '1'
	list addresses '10.103.4.1/24'

config wireguard_wg4 'wg4_ns_dddddddd_peer'
	option ns_ip '10.103.4.2'
	option ns_user 'alice'
	option public_key 'KEY_ALICE_4'

config interface 'wg5'
	option proto 'wireguard'
	option ns_type 'server'
	option ns_auth_mode 'typo'
	option ns_user_db 'wgauth_users'
	list addresses '10.103.5.1/24'
"""

users_db = """
config local 'wgauth_users'
	option description 'Main local database'

config ldap 'wgauth_ldap'
	option description 'Remote OpenLDAP server'
	option uri 'ldap://192.168.1.1'

config user 'ns_wgalice'
	option name 'alice'
	option database 'wgauth_users'
	option password '{password}'
	option openvpn_2fa '{secret}'

config user 'ns_wgcarol'
	option name 'carol'
	option database 'wgauth_users'
"""

wgauth_db = """
config main 'config'
	option port '9443'
	option idle_timeout '120'
"""


def _setup_db(tmp_path, port=True):
    conf_dir = tmp_path.joinpath("config")
    conf_dir.mkdir()
    with conf_dir.joinpath("network").open("w") as fp:
        fp.write(network_db)
    with conf_dir.joinpath("users").open("w") as fp:
        fp.write(users_db.format(password=users.shadow_password(PASSWORD), secret=OTP_SECRET))
    if port:
        with conf_dir.joinpath("ns-wgauth").open("w") as fp:
            fp.write(wgauth_db)
    # keep the changes saved by these tests out of the default savedir. libuci still applies the changes that
    # other tests saved there (test_users deletes the main database): the fixtures use names nobody else uses
    save_dir = tmp_path.joinpath("save")
    save_dir.mkdir()
    return EUci(confdir=conf_dir.as_posix(), savedir=save_dir.as_posix())


class FakeCommands:
    """Replace `wgauth._run`: answer nft, wg and ubus like the firewall would."""

    def __init__(self, table=None, handshakes="", endpoints="", failing=()):
        self.table = table
        self.handshakes = handshakes
        self.endpoints = endpoints
        # scripts nft refuses, matched by their first line
        self.failing = failing
        self.calls = []

    def __call__(self, cmd, input=None):
        self.calls.append((cmd, input))
        if cmd[:3] == ["nft", "-j", "list"]:
            if self.table is None:
                return subprocess.CompletedProcess(cmd, 1, "", "Error: No such file or directory")
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"nftables": self.table}), "")
        if cmd[0] == "nft" and cmd[-2:] == ["-f", "-"]:
            if any(input.startswith(script) for script in self.failing):
                return subprocess.CompletedProcess(cmd, 1, "", "Error: syntax error")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd == ["wg", "show", "all", "latest-handshakes"]:
            return subprocess.CompletedProcess(cmd, 0, self.handshakes, "")
        if cmd == ["wg", "show", "all", "endpoints"]:
            return subprocess.CompletedProcess(cmd, 0, self.endpoints, "")
        if cmd == ["wg", "pubkey"]:
            return subprocess.CompletedProcess(cmd, 0, SERVER_KEY + "\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def scripts(self):
        return [script for cmd, script in self.calls if cmd == ["nft", "-f", "-"]]

    def commands(self, name):
        return [cmd for cmd, _ in self.calls if cmd[0] == name]


REDIRECT = (wgauth.DEFAULT_REDIRECT_PORT, wgauth.DEFAULT_DNS_PORT)


def table_objects(servers, sessions=None, redirect=REDIRECT):
    """Objects of `nft -j list table inet ns_wgauth` for a table built by `build_ruleset`."""
    sessions = sessions or {}
    objects = [{"metainfo": {"version": "1.1.1"}}, {"table": {"family": "inet", "name": "ns_wgauth"}}]
    gated = {"family": "inet", "name": "gated", "table": "ns_wgauth", "type": "ifname"}
    if servers:
        gated["elem"] = list(servers)
    objects.append({"set": gated})
    for server in servers:
        nft_set = {"family": "inet", "name": f"auth_{server}", "table": "ns_wgauth", "type": "ipv4_addr"}
        elements = sessions.get(server, {})
        if elements:
            nft_set["elem"] = [
                {"elem": {"val": address, "timeout": 3600, "expires": left}} for address, left in elements.items()
            ]
        objects.append({"set": nft_set})
    for chain, count in wgauth.ruleset_shape(wgauth.build_ruleset(servers, 9443, redirect)).items():
        objects.append({"chain": {"family": "inet", "table": "ns_wgauth", "name": chain}})
        for _ in range(count):
            objects.append({"rule": {"family": "inet", "table": "ns_wgauth", "chain": chain, "expr": []}})
    return objects


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    path = tmp_path.joinpath("run")
    monkeypatch.setattr(wgauth, "RUN_DIR", path.as_posix())
    for name in ("sessions.json", "state.json", "blocked.json", "lock"):
        attribute = name.split(".")[0].upper() + "_FILE"
        monkeypatch.setattr(wgauth, attribute, path.joinpath(name).as_posix())
    monkeypatch.setattr(wgauth, "ALERTS_FILE", tmp_path.joinpath("etc", "alerts.json").as_posix())
    monkeypatch.setattr(wgauth, "DEVICES_FILE", tmp_path.joinpath("etc", "devices.json").as_posix())
    return path


def test_auth_modes(tmp_path):
    u = _setup_db(tmp_path)
    assert wgauth.get_auth_mode(u, "wg1") == "key_password"
    assert wgauth.get_auth_mode(u, "wg2") == "key"
    assert wgauth.is_gated(u, "wg1")
    assert not wgauth.is_gated(u, "wg2")
    # client tunnels are never gated
    assert not wgauth.is_gated(u, "wg3")
    # an unknown mode requires the login
    assert wgauth.is_gated(u, "wg5")
    assert not wgauth.requires_otp(u, "wg1")
    assert wgauth.requires_otp(u, "wg4")
    # disabled servers keep the gate
    assert wgauth.list_gated_servers(u) == ["wg1", "wg4", "wg5"]


def test_settings(tmp_path):
    u = _setup_db(tmp_path)
    assert wgauth.get_port(u) == 9443
    assert wgauth.get_idle_timeout(u) == 120
    assert wgauth.get_lock_endpoint(u) == "strict"
    u.set("ns-wgauth", "config", "lock_endpoint", "0")
    assert wgauth.get_lock_endpoint(u) == "off"
    u.set("ns-wgauth", "config", "lock_endpoint", "roaming")
    assert wgauth.get_lock_endpoint(u) == "roaming"
    # an unknown value keeps the lock
    u.set("ns-wgauth", "config", "lock_endpoint", "sometimes")
    assert wgauth.get_lock_endpoint(u) == "strict"
    assert wgauth.get_session_timeout(u, "wg1") == 3600
    assert wgauth.get_session_timeout(u, "wg4") == wgauth.DEFAULT_TIMEOUT
    assert wgauth.get_login_url(u, "wg1") == "http://10.103.1.1:9443/"
    assert wgauth.get_login_url(u, "wg3") is None
    u.set("network", "wg1", "ns_auth_timeout", "10")
    assert wgauth.get_session_timeout(u, "wg1") == wgauth.MIN_TIMEOUT


def test_default_settings(tmp_path):
    u = _setup_db(tmp_path, port=False)
    assert wgauth.get_port(u) == wgauth.DEFAULT_PORT
    assert wgauth.get_idle_timeout(u) == wgauth.DEFAULT_IDLE_TIMEOUT
    assert wgauth.get_login_url(u, "wg1") == f"http://10.103.1.1:{wgauth.DEFAULT_PORT}/"
    state = wgauth.build_state(u)
    assert state["redirect"] is True
    assert (state["redirect_port"], state["dns_port"]) == REDIRECT
    assert state["lock_endpoint"] == "strict"
    assert state["detect_copies"] is True
    assert state["block_copies"] is False
    assert state["max_failures"] == wgauth.DEFAULT_MAX_FAILURES
    assert state["lockout_time"] == wgauth.DEFAULT_LOCKOUT_TIME


def test_get_peer_user(tmp_path):
    u = _setup_db(tmp_path)
    assert wgauth.get_peer_user(u, "wg1", ALICE)["id"] == "ns_wgalice"
    # the user doesn't exist
    assert wgauth.get_peer_user(u, "wg1", "wg1_ns_bbbbbbbb_peer") is None
    # no user linked
    assert wgauth.get_peer_user(u, "wg1", "wg1_ns_eeeeeeee_peer") is None
    # only local databases
    u.set("network", "wg1", "ns_user_db", "wgauth_ldap")
    assert wgauth.get_peer_user(u, "wg1", ALICE) is None


def test_build_state(tmp_path):
    u = _setup_db(tmp_path)
    state = wgauth.build_state(u)
    assert sorted(state["servers"]) == ["wg1", "wg4", "wg5"]
    assert (state["port"], state["idle_timeout"], state["lock_endpoint"]) == (9443, 120, "strict")
    wg1 = state["servers"]["wg1"]
    assert (wg1["name"], wg1["enabled"], wg1["address"], wg1["otp"], wg1["timeout"]) == (
        "Road warriors",
        True,
        "10.103.1.1",
        False,
        3600,
    )
    # the disabled peer is missing, the peer without user has an empty one
    assert sorted(wg1["peers"]) == ["10.103.1.2", "10.103.1.4"]
    alice = wg1["peers"]["10.103.1.2"]
    assert (alice["peer"], alice["public_key"], alice["user"], alice["otp_secret"]) == (
        ALICE,
        "KEY_ALICE",
        "alice",
        OTP_SECRET,
    )
    assert users.check_password(PASSWORD, alice["password"])
    assert alice["fingerprint"] == wgauth.user_fingerprint(u, "wg1", users.get_user_by_name(u, "alice", "wgauth_users"))
    assert wg1["peers"]["10.103.1.4"]["user"] == ""
    assert state["servers"]["wg4"]["enabled"] is False
    assert state["servers"]["wg4"]["otp"] is True
    # the snapshot is plain JSON
    assert json.loads(json.dumps(state)) == state


def test_state_file(tmp_path, run_dir):
    assert wgauth.load_state() is None
    state = wgauth.build_state(_setup_db(tmp_path))
    wgauth.save_state(state)
    assert wgauth.load_state() == state
    if os.name == "posix":
        # password hashes and OTP secrets inside
        assert os.stat(wgauth.STATE_FILE).st_mode & 0o777 == 0o600
    with open(wgauth.STATE_FILE, "w") as fp:
        fp.write("{broken")
    assert wgauth.load_state() is None
    # written by another version: taken again
    with open(wgauth.STATE_FILE, "w") as fp:
        json.dump(dict(state, version=1), fp)
    assert wgauth.load_state() is None


def test_find_peer(tmp_path):
    state = wgauth.build_state(_setup_db(tmp_path))
    server, peer = wgauth.find_peer(state, "10.103.1.2")
    assert (server, peer["peer"]) == ("wg1", ALICE)
    # a peer without user can use the page, to be told so
    assert wgauth.find_peer(state, "10.103.1.4")[1]["user"] == ""
    # disabled peer
    assert wgauth.find_peer(state, "10.103.1.3") == (None, None)
    # server without login
    assert wgauth.find_peer(state, "10.103.2.2") == (None, None)
    # disabled server
    assert wgauth.find_peer(state, "10.103.4.2") == (None, None)
    assert wgauth.find_peer(state, "192.168.1.10") == (None, None)


def test_check_login(tmp_path):
    u = _setup_db(tmp_path)
    state = wgauth.build_state(u)
    alice = state["servers"]["wg1"]["peers"]["10.103.1.2"]
    assert wgauth.check_login(state, "wg1", alice, "alice", PASSWORD)
    assert wgauth.check_login(state, "wg1", alice, "ALICE", PASSWORD)
    assert not wgauth.check_login(state, "wg1", alice, "alice", "wrong")
    assert not wgauth.check_login(state, "wg1", alice, "alice", "")
    assert not wgauth.check_login(state, "wg1", alice, "alice", None)
    # the user must be the one linked to the peer
    assert not wgauth.check_login(state, "wg1", alice, "carol", PASSWORD)
    # no user linked
    nobody = state["servers"]["wg1"]["peers"]["10.103.1.4"]
    assert not wgauth.check_login(state, "wg1", nobody, "", PASSWORD)
    # a user without password can't log in
    u.set("network", ALICE, "ns_user", "carol")
    carol = wgauth.build_state(u)["servers"]["wg1"]["peers"]["10.103.1.2"]
    assert carol["user"] == "carol"
    assert not wgauth.check_login(state, "wg1", carol, "carol", "")


def test_check_login_otp(tmp_path):
    u = _setup_db(tmp_path)
    u.set("network", "wg1", "ns_auth_mode", "key_password_otp")
    state = wgauth.build_state(u)
    alice = state["servers"]["wg1"]["peers"]["10.103.1.2"]
    code = pyotp.TOTP(OTP_SECRET).now()
    assert not wgauth.check_login(state, "wg1", alice, "alice", PASSWORD)
    assert not wgauth.check_login(state, "wg1", alice, "alice", PASSWORD, "000000" if code != "000000" else "111111")
    assert not wgauth.check_login(state, "wg1", alice, "alice", PASSWORD, "12345")
    assert wgauth.check_login(state, "wg1", alice, "alice", PASSWORD, code)
    assert not wgauth.check_login(state, "wg1", alice, "alice", "wrong", code)
    assert not wgauth.otp_missing(state, "wg1", alice)
    # the secret is removed with the OpenVPN account: pyotp would accept the codes of an empty secret
    u.delete("users", "ns_wgalice", "openvpn_2fa")
    alice = wgauth.build_state(u)["servers"]["wg1"]["peers"]["10.103.1.2"]
    assert alice["otp_secret"] == ""
    assert wgauth.otp_missing(state, "wg1", alice)
    empty_code = pyotp.TOTP("").now()
    assert not wgauth.verify_otp("", empty_code)
    assert not wgauth.verify_otp(None, empty_code)
    assert not wgauth.check_login(state, "wg1", alice, "alice", PASSWORD, empty_code)


def test_saved_changes_wait_for_apply(tmp_path):
    u = _setup_db(tmp_path)
    state = wgauth.build_state(u)
    # changes saved but not applied: the snapshot taken at the last apply still holds
    u.set("network", "wg1", "ns_auth_mode", "key")
    u.set("users", "ns_wgalice", "password", users.shadow_password("new password"))
    alice = state["servers"]["wg1"]["peers"]["10.103.1.2"]
    assert wgauth.check_login(state, "wg1", alice, "alice", PASSWORD)
    assert "wg1" in state["servers"]
    # applied
    assert "wg1" not in wgauth.build_state(u)["servers"]


def test_ensure_otp_secret(tmp_path):
    u = _setup_db(tmp_path)
    alice = users.get_user_by_name(u, "alice", "wgauth_users")
    assert not wgauth.ensure_otp_secret(u, alice)
    carol = users.get_user_by_name(u, "carol", "wgauth_users")
    assert wgauth.ensure_otp_secret(u, carol)
    assert len(u.get("users", "ns_wgcarol", "openvpn_2fa")) == 32


def test_user_fingerprint(tmp_path):
    u = _setup_db(tmp_path)
    alice = users.get_user_by_name(u, "alice", "wgauth_users")
    fingerprint = wgauth.user_fingerprint(u, "wg1", alice)
    assert fingerprint == wgauth.user_fingerprint(u, "wg1", alice)
    assert fingerprint != wgauth.user_fingerprint(u, "wg1", dict(alice, password=users.shadow_password("new")))
    u.set("network", "wg1", "ns_auth_mode", "key_password_otp")
    with_otp = wgauth.user_fingerprint(u, "wg1", alice)
    assert with_otp != fingerprint
    assert with_otp != wgauth.user_fingerprint(u, "wg1", dict(alice, openvpn_2fa="ANOTHERSECRET234"))


def test_build_ruleset():
    script = wgauth.build_ruleset(["wg1", "wg4"], 8181)
    lines = script.splitlines()
    assert lines[0] == "add table inet ns_wgauth"
    assert 'add element inet ns_wgauth gated { "wg1", "wg4" }' in lines
    assert "add set inet ns_wgauth auth_wg1 { type ipv4_addr; flags timeout; }" in lines
    assert "add set inet ns_wgauth auth_wg4 { type ipv4_addr; flags timeout; }" in lines
    # sets are never flushed: the sessions survive
    assert not any(line.startswith("flush set inet ns_wgauth auth_") for line in lines)
    assert 'add rule inet ns_wgauth input iifname != @gated iifname != "lo" tcp dport 8181 drop' in lines
    assert 'add rule inet ns_wgauth input iifname "wg1" ip saddr != @auth_wg1 jump unauth_input' in lines
    assert 'add rule inet ns_wgauth forward oifname "wg4" ip daddr != @auth_wg4 drop' in lines
    assert "add rule inet ns_wgauth unauth_input tcp dport 8181 accept" in lines
    # no DNS before the login
    assert not any("dport 53" in line for line in lines)
    assert lines[-1] == "add rule inet ns_wgauth unauth_input reject with icmpx type admin-prohibited"
    # chains are created before the rules using them
    assert lines.index("add chain inet ns_wgauth unauth_input") < lines.index(
        'add rule inet ns_wgauth input iifname "wg1" ip saddr != @auth_wg1 jump unauth_input'
    )
    # without redirect the nat chain is removed, if it was there
    assert lines.index("flush chain inet ns_wgauth prerouting") < lines.index("delete chain inet ns_wgauth prerouting")
    assert "prerouting" not in wgauth.ruleset_shape(script)


def test_build_ruleset_redirect():
    script = wgauth.build_ruleset(["wg1"], 8181, (8180, 8153))
    lines = script.splitlines()
    assert "delete chain inet ns_wgauth prerouting" not in lines
    assert (
        "add chain inet ns_wgauth prerouting { type nat hook prerouting priority dstnat - 1; policy accept; }" in lines
    )
    assert (
        'add rule inet ns_wgauth prerouting iifname "wg1" ip saddr != @auth_wg1 udp dport 53 '
        f"limit rate {wgauth.DNS_RATE}/second redirect to :8153"
    ) in lines
    unauth = 'iifname "wg1" ip saddr != @auth_wg1'
    assert f"add rule inet ns_wgauth prerouting {unauth} tcp dport 80 redirect to :8180" in lines
    # the redirect ports are reachable only from the gated interfaces, and before the login
    assert 'add rule inet ns_wgauth input iifname != @gated iifname != "lo" tcp dport { 8181, 8180 } drop' in lines
    assert 'add rule inet ns_wgauth input iifname != @gated iifname != "lo" udp dport 8153 drop' in lines
    assert "add rule inet ns_wgauth unauth_input tcp dport { 8181, 8180 } accept" in lines
    assert "add rule inet ns_wgauth unauth_input udp dport 8153 accept" in lines
    # still nothing to the real DNS port of the firewall
    assert not any("unauth_input" in line and "dport 53" in line for line in lines)
    assert wgauth.ruleset_shape(script) == {"input": 4, "forward": 5, "unauth_input": 5, "prerouting": 2}


def _dns_query(name, qtype=1, ident=0x1234, flags=0x0100):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 1) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def test_dns_answer():
    reply = wgauth.dns_answer(_dns_query("neverssl.com"), "10.103.1.1")
    ident, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", reply[:12])
    assert (ident, questions, answers) == (0x1234, 1, 1)
    # a response, recursion desired copied, no error
    assert flags & 0x8000 and flags & 0x0100 and flags & 0x000F == 0
    question_end = 12 + len(b"\x08neverssl\x03com\x00") + 4
    assert reply[12:question_end] == _dns_query("neverssl.com")[12:]
    name, rtype, rclass, ttl, length = struct.unpack("!HHHIH", reply[question_end : question_end + 12])
    assert (name, rtype, rclass, ttl, length) == (0xC00C, 1, 1, wgauth.DNS_TTL, 4)
    assert reply[question_end + 12 :] == bytes([10, 103, 1, 1])
    # AAAA: no record, so the client uses IPv4
    reply = wgauth.dns_answer(_dns_query("neverssl.com", qtype=28), "10.103.1.1")
    assert struct.unpack("!HHHHHH", reply[:12])[3] == 0
    # not a query to answer
    assert wgauth.dns_answer(b"\x12\x34", "10.103.1.1") is None
    assert wgauth.dns_answer(_dns_query("example.com", flags=0x8180), "10.103.1.1") is None
    assert wgauth.dns_answer(_dns_query("example.com", flags=0x2800), "10.103.1.1") is None
    assert wgauth.dns_answer(_dns_query("example.com")[:-3], "10.103.1.1") is None
    compressed = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    assert wgauth.dns_answer(compressed, "10.103.1.1") is None


def test_build_block_ruleset():
    lines = wgauth.build_block_ruleset(["wg1", "wg4"]).splitlines()
    assert lines[:3] == ["add table inet ns_wgauth", "delete table inet ns_wgauth", "add table inet ns_wgauth"]
    assert "add chain inet ns_wgauth forward { type filter hook forward priority -1; policy accept; }" in lines
    for server in ("wg1", "wg4"):
        assert f'add rule inet ns_wgauth input iifname "{server}" drop' in lines
        assert f'add rule inet ns_wgauth forward iifname "{server}" drop' in lines
        assert f'add rule inet ns_wgauth forward oifname "{server}" drop' in lines
    # nothing that the login rules use: no sets, no symbolic priority, no reject
    assert not any("@" in line or "filter -" in line or "reject" in line for line in lines)


def test_table_matches():
    script = wgauth.build_ruleset(["wg1", "wg4"], 8181, REDIRECT)
    assert wgauth.table_matches(table_objects(["wg1", "wg4"]), ["wg1", "wg4"], script)
    assert not wgauth.table_matches(table_objects(["wg1"]), ["wg1", "wg4"], script)
    assert not wgauth.table_matches([], ["wg1"], script)
    broken = [item for item in table_objects(["wg1", "wg4"]) if item.get("rule", {}).get("chain") != "forward"]
    assert not wgauth.table_matches(broken, ["wg1", "wg4"], script)
    # the redirect turned off: the nat chain must go
    without = wgauth.build_ruleset(["wg1", "wg4"], 8181)
    assert not wgauth.table_matches(table_objects(["wg1", "wg4"]), ["wg1", "wg4"], without)
    assert wgauth.table_matches(table_objects(["wg1", "wg4"], redirect=None), ["wg1", "wg4"], without)


def test_parse_sessions():
    objects = table_objects(["wg1", "wg4"], {"wg1": {"10.103.1.2": 100, "10.103.1.4": 5}})
    # plain elements, without timeout
    objects.append({"set": {"name": "auth_wg9", "elem": ["10.103.9.2"]}})
    assert wgauth.parse_sessions(objects) == {
        "wg1": {"10.103.1.2": 100, "10.103.1.4": 5},
        "wg4": {},
        "wg9": {"10.103.9.2": 0},
    }


def test_check_script(mocker):
    fake = FakeCommands()
    mocker.patch("nethsec.wgauth._run", fake)
    assert wgauth.check_script("add table inet ns_wgauth\n") is None
    assert fake.calls[-1][0] == ["nft", "-c", "-f", "-"]
    fake.failing = ("add table",)
    assert wgauth.check_script("add table inet ns_wgauth\n") == "nft failed: Error: syntax error"
    # nothing applied
    assert fake.scripts() == []


def test_apply_ruleset(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    fake = FakeCommands(table=None)
    mocker.patch("nethsec.wgauth._run", fake)
    assert wgauth.apply_ruleset(state) == ["wg1", "wg4", "wg5"]
    assert fake.scripts() == [wgauth.build_ruleset(["wg1", "wg4", "wg5"], 9443, REDIRECT)]
    # complete table, nothing to do unless forced
    fake = FakeCommands(table=table_objects(["wg1", "wg4", "wg5"]))
    mocker.patch("nethsec.wgauth._run", fake)
    wgauth.apply_ruleset(state, force=False)
    assert fake.scripts() == []
    wgauth.apply_ruleset(state, force=True)
    assert len(fake.scripts()) == 1


def test_apply_ruleset_removes_old_sets(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    fake = FakeCommands(table=table_objects(["wg1", "wg2", "wg4", "wg5"]))
    mocker.patch("nethsec.wgauth._run", fake)
    wgauth.apply_ruleset(state, force=False)
    assert ["nft", "delete", "set", "inet", "ns_wgauth", "auth_wg2"] in fake.commands("nft")


def test_apply_ruleset_without_gated_servers(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    for server in ("wg1", "wg4", "wg5"):
        u.set("network", server, "ns_auth_mode", "key")
    state = wgauth.build_state(u)
    fake = FakeCommands(table=table_objects(["wg1"]))
    mocker.patch("nethsec.wgauth._run", fake)
    assert wgauth.apply_ruleset(state) == []
    assert fake.scripts() == ["delete table inet ns_wgauth\n"]
    fake = FakeCommands(table=None)
    mocker.patch("nethsec.wgauth._run", fake)
    wgauth.apply_ruleset(state)
    assert fake.scripts() == []


def test_apply_ruleset_failure_blocks(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    log = mocker.patch("nethsec.wgauth.log")
    fake = FakeCommands(table=None, failing=("add table inet ns_wgauth\nadd set",))
    mocker.patch("nethsec.wgauth._run", fake)
    with pytest.raises(RuntimeError):
        wgauth.apply_ruleset(state)
    # fail closed: the whole VPN of the gated servers is blocked
    assert fake.scripts()[-1] == wgauth.build_block_ruleset(["wg1", "wg4", "wg5"])
    assert wgauth.gate_status()["blocked"] == ["wg1", "wg4", "wg5"]
    assert log.call_count == 1
    # the next attempts don't log the same error again
    with pytest.raises(RuntimeError):
        wgauth.apply_ruleset(state, force=False)
    assert log.call_count == 1
    # the rules work again
    fake.failing = ()
    wgauth.apply_ruleset(state, force=False)
    assert wgauth.gate_status()["blocked"] == []
    assert fake.commands("ubus") == []


def test_apply_ruleset_failure_keeps_complete_table(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    fake = FakeCommands(table=table_objects(["wg1", "wg4", "wg5"]), failing=("add table inet ns_wgauth\nadd set",))
    mocker.patch("nethsec.wgauth._run", fake)
    with pytest.raises(RuntimeError):
        wgauth.apply_ruleset(state)
    # the rules in place still gate every server and keep the sessions
    assert len(fake.scripts()) == 1
    assert wgauth.gate_status()["blocked"] == []


def test_apply_ruleset_failure_takes_interfaces_down(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    mocker.patch("nethsec.wgauth.log")
    fake = FakeCommands(table=None, failing=("add table",))
    mocker.patch("nethsec.wgauth._run", fake)
    with pytest.raises(RuntimeError):
        wgauth.apply_ruleset(state)
    downs = [json.loads(cmd[-1])["interface"] for cmd in fake.commands("ubus") if cmd[3] == "down"]
    assert downs == ["wg1", "wg4", "wg5"]
    fake.failing = ()
    fake.calls = []
    wgauth.apply_ruleset(state)
    # the disabled server stays down
    ups = [json.loads(cmd[-1])["interface"] for cmd in fake.commands("ubus") if cmd[3] == "up"]
    assert ups == ["wg1", "wg5"]
    assert wgauth.gate_status()["blocked"] == []


def _alice(state):
    return state["servers"]["wg1"]["peers"]["10.103.1.2"]


def test_open_and_close_session(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    fake = FakeCommands(table=table_objects(["wg1", "wg4", "wg5"]))
    mocker.patch("nethsec.wgauth._run", fake)
    mocker.patch("nethsec.wgauth.log")
    expires = wgauth.open_session(state, "wg1", "10.103.1.2", _alice(state), "203.0.113.7")
    assert expires - time.time() == pytest.approx(3600, abs=5)
    assert fake.scripts()[-1].splitlines() == [
        "add element inet ns_wgauth auth_wg1 { 10.103.1.2 }",
        "delete element inet ns_wgauth auth_wg1 { 10.103.1.2 }",
        "add element inet ns_wgauth auth_wg1 { 10.103.1.2 timeout 3600s }",
    ]
    # the DNS queries and web requests redirected before the login reach their destination now
    assert ["conntrack", "-D", "-s", "10.103.1.2", "-p", "udp", "--dport", "53"] in fake.commands("conntrack")
    assert ["conntrack", "-D", "-s", "10.103.1.2", "-p", "tcp", "--dport", "80"] in fake.commands("conntrack")
    entry = wgauth.load_metadata()["wg1"]["10.103.1.2"]
    assert entry["peer"] == ALICE
    assert entry["public_key"] == "KEY_ALICE"
    assert entry["user"] == "alice"
    assert entry["fingerprint"] == _alice(state)["fingerprint"]
    assert entry["endpoint"] == "203.0.113.7"

    fake.table = table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3500}})
    assert wgauth.close_session("wg1", "10.103.1.2", "logout")
    assert fake.scripts()[-1].splitlines() == [
        "add element inet ns_wgauth auth_wg1 { 10.103.1.2 }",
        "delete element inet ns_wgauth auth_wg1 { 10.103.1.2 }",
    ]
    assert ["conntrack", "-D", "-s", "10.103.1.2"] in fake.commands("conntrack")
    assert ["conntrack", "-D", "-d", "10.103.1.2"] in fake.commands("conntrack")
    assert wgauth.load_metadata() == {}


def test_open_session_rejects_bad_address(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    mocker.patch("nethsec.wgauth._run", FakeCommands(table=table_objects(["wg1"])))
    with pytest.raises(ValueError):
        wgauth.open_session(state, "wg1", "10.103.1.2 }; flush ruleset", _alice(state))


def _session(state, **changes):
    alice = _alice(state)
    entry = {"peer": ALICE, "public_key": "KEY_ALICE", "user": "alice", "fingerprint": alice["fingerprint"]}
    entry.update(changes)
    return entry


def test_session_problem(tmp_path):
    u = _setup_db(tmp_path)
    state = wgauth.build_state(u)
    now = int(time.time())
    entry = _session(state)
    fresh = {"KEY_ALICE": now - 30}

    def problem(server="wg1", address="10.103.1.2", entry=entry, handshakes=fresh, blocked=(), state=state):
        return wgauth.session_problem(state, server, address, entry, handshakes, now, blocked=blocked)

    assert problem() is None
    assert problem(entry=None) == "unknown_session"
    assert problem(server="wg2") == "server_changed"
    assert problem(address="10.103.1.9") == "peer_changed"
    assert problem(entry=_session(state, peer="wg1_ns_bbbbbbbb_peer")) == "peer_changed"
    # new keys generated for the peer
    assert problem(entry=_session(state, public_key="OLD_KEY")) == "peer_changed"
    assert problem(entry=_session(state, user="carol")) == "user_changed"
    assert problem(blocked={ALICE}) == "blocked"
    assert problem(handshakes={"KEY_ALICE": now - 600}) == "disconnected"
    assert problem(handshakes={}) == "disconnected"
    # without handshake information, or with the check disabled, the session stays
    assert problem(handshakes=None) is None
    assert problem(handshakes={}, state=dict(state, idle_timeout=0)) is None

    u.set("users", "ns_wgalice", "password", users.shadow_password("new password"))
    # not applied yet
    assert problem() is None
    assert problem(state=wgauth.build_state(u)) == "user_changed"


def test_session_problem_server_and_peer_disabled(tmp_path):
    u = _setup_db(tmp_path)
    state = wgauth.build_state(u)
    now = int(time.time())
    entry = _session(state)
    u.set("network", ALICE, "disabled", "1")
    assert wgauth.session_problem(wgauth.build_state(u), "wg1", "10.103.1.2", entry, None, now) == "peer_changed"
    u.set("network", ALICE, "disabled", "0")
    u.set("network", "wg1", "disabled", "1")
    assert wgauth.session_problem(wgauth.build_state(u), "wg1", "10.103.1.2", entry, None, now) == "server_changed"


def test_endpoints(mocker):
    assert wgauth.endpoint_address("203.0.113.7:51820") == "203.0.113.7"
    assert wgauth.endpoint_address("[2001:db8::1]:51820") == "2001:db8::1"
    fake = FakeCommands(endpoints="wg1\tKEY_A\t203.0.113.7:51820\nwg1\tKEY_B\t(none)\nwg2\tKEY_C\t[2001:db8::1]:4500\n")
    mocker.patch("nethsec.wgauth._run", fake)
    assert wgauth.read_endpoints() == {"KEY_A": "203.0.113.7", "KEY_C": "2001:db8::1"}


def test_session_problem_endpoint(tmp_path):
    state = wgauth.build_state(_setup_db(tmp_path))
    now = int(time.time())
    entry = _session(state, endpoint="203.0.113.7")

    def problem(endpoints, lock="strict"):
        return wgauth.session_problem(dict(state, lock_endpoint=lock), "wg1", "10.103.1.2", entry, None, now, endpoints)

    assert problem({"KEY_ALICE": "203.0.113.7"}) is None
    # the same key from another public IP
    assert problem({"KEY_ALICE": "198.51.100.20"}) == "endpoint_changed"
    # the session follows the peer
    assert problem({"KEY_ALICE": "198.51.100.20"}, lock="roaming") is None
    # unknown endpoint, for example after an interface restart
    assert problem({}) is None
    # check disabled
    assert problem(None) is None
    # endpoint not recorded at login
    entry.pop("endpoint")
    assert problem({"KEY_ALICE": "198.51.100.20"}) is None


def test_reconcile_endpoint(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    state = wgauth.build_state(u)
    now = int(time.time())
    fake = FakeCommands(
        table=table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3000}}),
        handshakes=f"wg1\tKEY_ALICE\t{now - 10}\n",
        endpoints="wg1\tKEY_ALICE\t203.0.113.7:40001\n",
    )
    mocker.patch("nethsec.wgauth._run", fake)
    log = mocker.patch("nethsec.wgauth.log")
    # the endpoint wasn't known at login: recorded now
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(state)}})
    assert wgauth.reconcile(state) == []
    assert wgauth.load_metadata()["wg1"]["10.103.1.2"]["endpoint"] == "203.0.113.7"
    # the same key from another public IP ends the session
    fake.endpoints = "wg1\tKEY_ALICE\t198.51.100.20:51820\n"
    assert wgauth.reconcile(state) == [("wg1", "10.103.1.2", "endpoint_changed")]
    assert any("sends from 198.51.100.20, it logged in from 203.0.113.7" in call.args[0] for call in log.call_args_list)
    # roaming: the session follows the peer
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(state, endpoint="203.0.113.7")}})
    u.set("ns-wgauth", "config", "lock_endpoint", "roaming")
    state = wgauth.build_state(u)
    assert wgauth.reconcile(state) == []
    assert wgauth.load_metadata()["wg1"]["10.103.1.2"]["endpoint"] == "198.51.100.20"
    # the lock can be disabled
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(state, endpoint="203.0.113.7")}})
    u.set("ns-wgauth", "config", "lock_endpoint", "0")
    state = wgauth.build_state(u)
    assert wgauth.reconcile(state) == []
    assert wgauth.load_metadata()["wg1"]["10.103.1.2"]["endpoint"] == "203.0.113.7"


def test_session_survives_interface_restart(tmp_path):
    state = wgauth.build_state(_setup_db(tmp_path))
    now = int(time.time())

    def problem(entry):
        return wgauth.session_problem(dict(state, idle_timeout=300), "wg1", "10.103.1.2", entry, {}, now)

    # the interface restarted: no handshake yet, but the latest one seen is recent
    assert problem(_session(state, login=now - 3600, seen=now - 100)) is None
    assert problem(_session(state, login=now - 3600, seen=now - 400)) == "disconnected"
    # a recent login counts as a handshake
    assert problem(_session(state, login=now - 10)) is None
    # corrupted metadata counts as no handshake
    assert problem(_session(state, login="yesterday", seen=True)) == "disconnected"


def test_reconcile(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    now = int(time.time())
    fake = FakeCommands(
        table=table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3000, "10.103.1.9": 3000}}),
        handshakes=f"wg1\tKEY_ALICE\t{now - 10}\nwg1\tKEY_BOB\t0\n",
    )
    mocker.patch("nethsec.wgauth._run", fake)
    mocker.patch("nethsec.wgauth.log")
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(state), "10.103.1.7": _session(state)}})
    ended = wgauth.reconcile(state)
    assert sorted(ended) == [("wg1", "10.103.1.7", "expired"), ("wg1", "10.103.1.9", "unknown_session")]
    assert list(wgauth.load_metadata()["wg1"]) == ["10.103.1.2"]
    # the latest handshake is remembered
    assert wgauth.load_metadata()["wg1"]["10.103.1.2"]["seen"] == now - 10
    # the interface restarted: the handshakes are gone, the session stays
    fake.handshakes = ""
    fake.table = table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3000}})
    assert wgauth.reconcile(state) == []
    # the idle check uses the configured timeout
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(state, seen=now - 200)}})
    fake.handshakes = f"wg1\tKEY_ALICE\t{now - 200}\n"
    assert wgauth.reconcile(state) == [("wg1", "10.103.1.2", "disconnected")]
    assert wgauth.load_metadata() == {}


def test_reconcile_blocked(tmp_path, mocker, run_dir):
    state = wgauth.build_state(_setup_db(tmp_path))
    now = int(time.time())
    fake = FakeCommands(
        table=table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3000}}),
        handshakes=f"wg1\tKEY_ALICE\t{now - 10}\n",
    )
    mocker.patch("nethsec.wgauth._run", fake)
    mocker.patch("nethsec.wgauth.log")
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(state)}})
    wgauth.add_alert(ALICE, "KEY_ALICE", "copy", "alice", ["203.0.113.7"], block=True)
    assert wgauth.reconcile(state) == [("wg1", "10.103.1.2", "blocked")]


def test_alerts(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    mocker.patch("nethsec.wgauth.log")
    alice = _alice(wgauth.build_state(u))
    assert wgauth.load_alerts() == {}
    assert not wgauth.is_blocked(alice)
    wgauth.add_alert(ALICE, "KEY_ALICE", "lockout", "alice", ["198.51.100.20", ""])
    entry = wgauth.peer_alerts(wgauth.load_alerts(), ALICE, "KEY_ALICE")
    assert entry["blocked"] is False
    assert [(event["type"], event["addresses"]) for event in entry["events"]] == [("lockout", ["198.51.100.20"])]
    assert not wgauth.is_blocked(alice)
    wgauth.add_alert(ALICE, "KEY_ALICE", "copy", "alice", ["203.0.113.7", "198.51.100.20"], block=True)
    assert wgauth.is_blocked(alice)
    # the alerts belong to the keys of the peer
    assert wgauth.peer_alerts(wgauth.load_alerts(), ALICE, "NEW_KEY") is None
    assert not wgauth.is_blocked(dict(alice, public_key="NEW_KEY"))
    # only the latest events are kept
    for _ in range(wgauth.MAX_ALERTS + 5):
        wgauth.add_alert(ALICE, "KEY_ALICE", "lockout", "alice", ["198.51.100.20"])
    assert len(wgauth.load_alerts()[ALICE]["events"]) == wgauth.MAX_ALERTS
    assert wgauth.is_blocked(alice)
    assert wgauth.clear_alerts(ALICE)
    assert not wgauth.clear_alerts(ALICE)
    assert not wgauth.is_blocked(alice)


def test_prune_alerts(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    mocker.patch("nethsec.wgauth.log")
    wgauth.add_alert(ALICE, "KEY_ALICE", "copy", "alice", ["203.0.113.7"])
    wgauth.add_alert("wg1_ns_eeeeeeee_peer", "KEY_NOBODY", "copy", "", ["203.0.113.7"])
    wgauth.add_alert("wg1_ns_ffffffff_peer", "KEY_REMOVED", "copy", "dave", ["203.0.113.7"])
    # new keys for the peer without user, the last peer removed
    u.set("network", "wg1_ns_eeeeeeee_peer", "public_key", "KEY_NEW")
    wgauth.prune_alerts(u)
    assert list(wgauth.load_alerts()) == [ALICE]


def test_copy_detector():
    detector = wgauth.CopyDetector()
    now = 1000
    assert detector.observe({"KEY": "203.0.113.7"}, now) == {}
    # one device moving to other networks
    assert detector.observe({"KEY": "198.51.100.20"}, now + 10) == {}
    assert detector.observe({"KEY": "192.0.2.30"}, now + 20) == {}
    assert detector.observe({"KEY": "192.0.2.40"}, now + 30) == {}
    # two devices: the endpoint switches back and forth
    detector = wgauth.CopyDetector()
    detector.observe({"KEY": "203.0.113.7", "OTHER": "192.0.2.1"}, now)
    assert detector.observe({"KEY": "198.51.100.20"}, now + 25) == {}
    assert detector.observe({"KEY": "203.0.113.7"}, now + 50) == {}
    assert detector.observe({"KEY": "198.51.100.20"}, now + 75) == {"KEY": ["198.51.100.20", "203.0.113.7"]}
    # counted again from zero
    assert detector.observe({"KEY": "203.0.113.7"}, now + 100) == {}
    # changes older than the window don't count
    detector = wgauth.CopyDetector()
    detector.observe({"KEY": "203.0.113.7"}, now)
    detector.observe({"KEY": "198.51.100.20"}, now + 10)
    detector.observe({"KEY": "203.0.113.7"}, now + 400)
    assert detector.observe({"KEY": "198.51.100.20"}, now + 410) == {}
    # a key gone, for example a peer removed, is forgotten
    detector.observe({}, now + 420)
    assert detector.last == {} and detector.history == {}


def test_report_copy(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    state = wgauth.build_state(u)
    fake = FakeCommands(table=table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3000}}))
    mocker.patch("nethsec.wgauth._run", fake)
    log = mocker.patch("nethsec.wgauth.log")
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(state)}})
    assert wgauth.report_copy(state, "KEY_UNKNOWN", ["203.0.113.7"]) is None
    assert wgauth.report_copy(state, "KEY_ALICE", ["198.51.100.20", "203.0.113.7"]) == ALICE
    assert any("possible copy of the configuration of peer" in call.args[0] for call in log.call_args_list)
    assert wgauth.load_metadata() == {}
    events = wgauth.load_alerts()[ALICE]["events"]
    assert [(event["type"], event["addresses"]) for event in events] == [("copy", ["198.51.100.20", "203.0.113.7"])]
    # alert only by default
    assert not wgauth.is_blocked(_alice(state))
    # seen again soon: the session ends, but no new alert
    wgauth.report_copy(state, "KEY_ALICE", ["198.51.100.20", "203.0.113.7"])
    assert len(wgauth.load_alerts()[ALICE]["events"]) == 1
    # with block_copies the peer is blocked, even if already reported
    u.set("ns-wgauth", "config", "block_copies", "1")
    state = wgauth.build_state(u)
    wgauth.report_copy(state, "KEY_ALICE", ["198.51.100.20", "203.0.113.7"])
    assert wgauth.is_blocked(_alice(state))


def test_login_failures():
    failures = wgauth.LoginFailures()
    now = 1000
    for attempt in range(4):
        assert failures.add(ALICE, "198.51.100.20", now + attempt, 5, 900) == []
    assert failures.locked_until(ALICE, "198.51.100.20", now + 4, 5, 900) is None
    # the fifth failure locks out that IP
    assert failures.add(ALICE, "198.51.100.20", now + 4, 5, 900) == ["198.51.100.20"]
    assert failures.locked_until(ALICE, "198.51.100.20", now + 5, 5, 900) == now + 4 + 900
    # the real user, from another network, can still log in
    assert failures.locked_until(ALICE, "203.0.113.7", now + 5, 5, 900) is None
    # other peers aren't affected
    assert failures.locked_until("wg1_other_peer", "198.51.100.20", now + 5, 5, 900) is None
    # the lockout ends
    assert failures.locked_until(ALICE, "198.51.100.20", now + 905, 5, 900) is None
    # a successful login forgets the failures of its IP only
    failures.add(ALICE, "203.0.113.7", now + 906, 5, 900)
    failures.add(ALICE, "198.51.100.21", now + 906, 5, 900)
    failures.success(ALICE, "203.0.113.7")
    assert [source for _, source in failures.failures[ALICE]] == ["198.51.100.21"]


def test_login_failures_from_many_ips():
    failures = wgauth.LoginFailures()
    now = 1000
    failures.success(ALICE, "203.0.113.7")
    locked = []
    for attempt in range(5 * wgauth.PEER_FAILURE_FACTOR):
        locked = failures.add(ALICE, f"198.51.100.{attempt}", now + attempt, 5, 900)
    # too many failures for the peer: every IP is locked out but the one of the latest login
    assert len(locked) == 5 * wgauth.PEER_FAILURE_FACTOR
    assert failures.locked_until(ALICE, "192.0.2.99", now + 30, 5, 900) is not None
    assert failures.locked_until(ALICE, "203.0.113.7", now + 30, 5, 900) is None


def _bind_devices(u, machine_id=False):
    u.set("network", "wg1", "ns_device_binding", "1")
    # the devices sign the public key of the server
    u.set("network", "wg1", "private_key", "PRIVATE")
    if machine_id:
        u.set("network", "wg1", "ns_machine_id", "1")
    u.save("network")


class Device:
    """A device with a P-256 key, made and used with openssl like a client would."""

    def __init__(self, path):
        path.mkdir(parents=True, exist_ok=True)
        self.key = path.joinpath("key.pem").as_posix()
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.key], check=True)
        der = subprocess.run(
            ["openssl", "ec", "-in", self.key, "-pubout", "-outform", "DER"], check=True, capture_output=True
        ).stdout
        self.public_key = base64.b64encode(der).decode()

    def sign(self, message):
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.key], input=message, check=True, capture_output=True
        ).stdout
        return base64.b64encode(signature).decode()

    def proof(self, challenge, username="alice", address="10.103.1.2", peer_key="KEY_ALICE", machine_id=""):
        message = wgauth.device_message(challenge, SERVER_KEY, peer_key, address, username, machine_id)
        proof = {
            "challenge": challenge,
            "signature": self.sign(message),
            "public_key": self.public_key,
            "kind": "software",
            "name": "LAPTOP-42\n",
        }
        if machine_id:
            proof["machine_id"] = machine_id
        return proof


needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is missing")


def test_device_options(tmp_path):
    u = _setup_db(tmp_path)
    assert not wgauth.requires_device(u, "wg1")
    assert not wgauth.requires_machine_id(u, "wg1")
    _bind_devices(u)
    assert wgauth.requires_device(u, "wg1")
    assert not wgauth.requires_machine_id(u, "wg1")
    u.set("network", "wg1", "ns_machine_id", "1")
    assert wgauth.requires_machine_id(u, "wg1")
    # a server without the login can't require devices
    u.set("network", "wg2", "ns_device_binding", "1")
    u.set("network", "wg2", "ns_machine_id", "1")
    assert not wgauth.requires_device(u, "wg2")
    assert not wgauth.requires_machine_id(u, "wg2")
    # a typo must not turn the binding off
    u.set("network", "wg1", "ns_device_binding", "maybe")
    assert wgauth.requires_device(u, "wg1")


def test_build_state_devices(tmp_path, mocker):
    u = _setup_db(tmp_path)
    _bind_devices(u, machine_id=True)
    commands = FakeCommands()
    mocker.patch("nethsec.wgauth._run", commands)
    state = wgauth.build_state(u)
    assert state["servers"]["wg1"]["device_binding"]
    assert state["servers"]["wg1"]["machine_id"]
    assert state["servers"]["wg1"]["public_key"] == SERVER_KEY
    assert (["wg", "pubkey"], "PRIVATE") in commands.calls
    # no key needed without the binding
    assert not state["servers"]["wg4"]["device_binding"]
    assert state["servers"]["wg4"]["public_key"] == ""
    # every peer of every server, disabled and without the login too
    assert state["peer_keys"][ALICE] == "KEY_ALICE"
    assert state["peer_keys"]["wg1_ns_bbbbbbbb_peer"] == "KEY_BOB"
    assert state["peer_keys"]["wg2_ns_cccccccc_peer"] == ""
    assert state["enroll_window"] == wgauth.DEFAULT_ENROLL_WINDOW


def test_device_message():
    message = wgauth.device_message("CHALLENGE", "SERVER", "PEER", "10.103.1.2", "Alice", "ab" * 32)
    assert message == b"ns-wgauth-device-v1\nCHALLENGE\nSERVER\nPEER\n10.103.1.2\nAlice\n" + b"ab" * 32
    assert wgauth.device_message("C", "S", "P", "10.103.1.2", "alice").endswith(b"\nalice\n")


def test_decode_public_key():
    point = bytes([4]) + bytes(range(64))
    der = wgauth.P256_SPKI_PREFIX + point
    assert wgauth.decode_public_key(base64.b64encode(der).decode()) == der
    # compressed point, another algorithm, too short
    for bad in (
        wgauth.P256_SPKI_PREFIX + bytes([2]) + bytes(range(64)),
        bytes(len(wgauth.P256_SPKI_PREFIX)) + point,
        der[:-1],
    ):
        assert wgauth.decode_public_key(base64.b64encode(bad).decode()) is None
    for bad in ("not base64!", "", None, 42):
        assert wgauth.decode_public_key(bad) is None


def test_challenges():
    challenges = wgauth.Challenges(ttl=60, keep=2)
    first = challenges.issue("10.103.1.2", 1000)
    second = challenges.issue("10.103.1.2", 1001)
    assert first != second
    # from another address, unknown or empty: refused
    assert not challenges.use("10.103.1.3", first, 1002)
    assert not challenges.use("10.103.1.2", "forged", 1002)
    assert not challenges.use("10.103.1.2", "", 1002)
    assert not challenges.use("10.103.1.2", None, 1002)
    # once only
    assert challenges.use("10.103.1.2", first, 1002)
    assert not challenges.use("10.103.1.2", first, 1002)
    # expired
    assert not challenges.use("10.103.1.2", second, 1061)
    # only the latest are kept
    issued = [challenges.issue("10.103.1.2", 2000) for _ in range(3)]
    assert not challenges.use("10.103.1.2", issued[0], 2001)
    assert challenges.use("10.103.1.2", issued[2], 2001)
    # the expired ones are forgotten
    challenges.issue("10.103.1.9", 5000)
    assert list(challenges.issued) == ["10.103.1.9"]


def test_sync_devices(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    mocker.patch("nethsec.wgauth._run", FakeCommands())
    state = wgauth.build_state(u)
    # without binding, nothing is written
    assert wgauth.sync_devices(state, now=1000) == {}
    _bind_devices(u)
    state = wgauth.build_state(u)
    devices = wgauth.sync_devices(state, now=1000)
    # the enabled peers of the server, with or without a user
    assert sorted(devices) == [ALICE, "wg1_ns_eeeeeeee_peer"]
    assert devices[ALICE] == {"public_key": "KEY_ALICE", "window_until": 1000 + 72 * 3600, "device": None}
    assert wgauth.device_state(devices[ALICE], 1001) == "waiting"
    assert wgauth.device_state(devices[ALICE], 1000 + 72 * 3600) == "closed"
    assert wgauth.device_state(None, 1001) == "closed"
    # the window isn't opened again
    assert wgauth.sync_devices(state, now=500000)[ALICE]["window_until"] == 1000 + 72 * 3600
    # a revoked peer stays closed
    assert not wgauth.revoke_device(ALICE, "KEY_ALICE")
    assert wgauth.sync_devices(state, now=500000)[ALICE]["window_until"] == 0
    # new keys: a new window
    u.set("network", ALICE, "public_key", "KEY_ALICE_NEW")
    state = wgauth.build_state(u)
    devices = wgauth.sync_devices(state, now=600000)
    assert devices[ALICE] == {"public_key": "KEY_ALICE_NEW", "window_until": 600000 + 72 * 3600, "device": None}
    # a removed peer is forgotten
    state["peer_keys"].pop("wg1_ns_eeeeeeee_peer")
    state["servers"]["wg1"]["peers"].pop("10.103.1.4")
    assert "wg1_ns_eeeeeeee_peer" not in wgauth.sync_devices(state, now=600000)
    # the administrator opens the enrollment
    until = wgauth.allow_enrollment(ALICE, "KEY_ALICE_NEW", 3600)
    assert abs(until - time.time() - 3600) < 5
    assert wgauth.device_state(wgauth.load_devices()[ALICE]) == "waiting"


@needs_openssl
def test_verify_signature(tmp_path, run_dir):
    device = Device(tmp_path.joinpath("device"))
    der = wgauth.decode_public_key(device.public_key)
    signature = base64.b64decode(device.sign(b"hello"))
    assert wgauth.verify_signature(der, b"hello", signature)
    assert not wgauth.verify_signature(der, b"hello!", signature)
    assert not wgauth.verify_signature(der, b"hello", signature[:-1] + bytes([signature[-1] ^ 1]))
    # the temporary files are removed
    assert os.listdir(run_dir) == []


def _device_state(tmp_path, mocker, machine_id=False):
    u = _setup_db(tmp_path)
    _bind_devices(u, machine_id)
    mocker.patch("nethsec.wgauth._run", FakeCommands())
    state = wgauth.build_state(u)
    wgauth.sync_devices(state, now=int(time.time()))
    _server, peer = wgauth.find_peer(state, "10.103.1.2")
    return state, peer


def _entry(peer):
    return wgauth.peer_device(wgauth.load_devices(), peer["peer"], peer["public_key"])


@needs_openssl
def test_verify_device_enrollment(tmp_path, mocker, run_dir):
    state, peer = _device_state(tmp_path, mocker)
    device = Device(tmp_path.joinpath("device"))
    verify = wgauth.verify_device
    # during the window a device enrolls with its first successful login
    error, enrolled = verify(state, "wg1", "10.103.1.2", peer, "alice", device.proof("C1"), _entry(peer))
    assert error is None
    assert enrolled == {"key": device.public_key, "kind": "software", "name": "LAPTOP-42", "machine_id": ""}
    assert wgauth.record_device_login(peer, enrolled, "", "203.0.113.7")
    entry = _entry(peer)
    assert wgauth.device_state(entry) == "enrolled"
    assert entry["window_until"] == 0
    assert entry["device"]["endpoint"] == "203.0.113.7"
    # then only that device
    assert verify(state, "wg1", "10.103.1.2", peer, "alice", device.proof("C2"), entry) == (None, None)
    other = Device(tmp_path.joinpath("other"))
    assert verify(state, "wg1", "10.103.1.2", peer, "alice", other.proof("C3"), entry) == ("device_mismatch", None)
    # the key of the device with the signature of another one
    proof = other.proof("C3")
    proof["public_key"] = device.public_key
    assert verify(state, "wg1", "10.103.1.2", peer, "alice", proof, entry)[0] == "device_mismatch"
    # a signature for another challenge, user, address or peer
    for changed in ({"challenge": "C9"}, {"username": "bob"}, {"address": "10.103.1.4"}, {"peer_key": "KEY_BOB"}):
        proof = device.proof(**dict({"challenge": "C4"}, **changed))
        proof["challenge"] = "C4"
        assert verify(state, "wg1", "10.103.1.2", peer, "alice", proof, entry)[0] == "device_mismatch"
    # a malformed proof
    for broken in ({"signature": "!"}, {"public_key": 1}, {"challenge": "a\nb"}, {"machine_id": "XYZ"}):
        proof = dict(device.proof("C5"), **broken)
        assert verify(state, "wg1", "10.103.1.2", peer, "alice", proof, entry)[0] == "device_mismatch"
    # a second enrollment can't happen
    assert not wgauth.record_device_login(peer, enrolled, "", "203.0.113.7")
    # the last use is recorded
    assert wgauth.record_device_login(peer, None, "", "198.51.100.1")
    assert _entry(peer)["device"]["endpoint"] == "198.51.100.1"


@needs_openssl
def test_verify_device_closed(tmp_path, mocker, run_dir):
    state, peer = _device_state(tmp_path, mocker)
    device = Device(tmp_path.joinpath("device"))
    wgauth.revoke_device(peer["peer"], peer["public_key"])
    proof = device.proof("C1")
    error = wgauth.verify_device(state, "wg1", "10.103.1.2", peer, "alice", proof, _entry(peer))
    assert error == ("device_not_enrolled", None)
    assert not wgauth.record_device_login(peer, None, "", "203.0.113.7")
    # without the public key of the server nothing can be checked
    wgauth.allow_enrollment(peer["peer"], peer["public_key"])
    state["servers"]["wg1"]["public_key"] = ""
    assert wgauth.verify_device(state, "wg1", "10.103.1.2", peer, "alice", proof, _entry(peer))[0] == "device_mismatch"


@needs_openssl
def test_verify_device_machine_id(tmp_path, mocker, run_dir):
    state, peer = _device_state(tmp_path, mocker, machine_id=True)
    device = Device(tmp_path.joinpath("device"))
    machine = "ab" * 32
    verify = wgauth.verify_device
    # required: a device without it can't enroll
    assert verify(state, "wg1", "10.103.1.2", peer, "alice", device.proof("C1"), _entry(peer))[0] == "device_mismatch"
    proof = device.proof("C2", machine_id=machine)
    error, enrolled = verify(state, "wg1", "10.103.1.2", peer, "alice", proof, _entry(peer))
    assert error is None and enrolled["machine_id"] == machine
    assert wgauth.record_device_login(peer, enrolled, machine, "203.0.113.7")
    entry = _entry(peer)
    proof = device.proof("C3", machine_id=machine)
    assert verify(state, "wg1", "10.103.1.2", peer, "alice", proof, entry) == (None, None)
    # the same key on another machine
    proof = device.proof("C4", machine_id="cd" * 32)
    assert verify(state, "wg1", "10.103.1.2", peer, "alice", proof, entry)[0] == "device_mismatch"
    # enrolled before the server asked for it: the first ID is recorded
    entry["device"]["machine_id"] = ""
    assert verify(state, "wg1", "10.103.1.2", peer, "alice", proof, entry) == (None, None)
    wgauth.save_devices({peer["peer"]: entry})
    assert wgauth.record_device_login(peer, None, "cd" * 32, "203.0.113.7")
    assert _entry(peer)["device"]["machine_id"] == "cd" * 32
