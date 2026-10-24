import json
import subprocess
import time

import pyotp
import pytest
from euci import EUci
from nethsec import users, wgauth

OTP_SECRET = "JBSWY3DPEHPK3PXP"
PASSWORD = "Secret,1234"

network_db = """
config interface 'lan'
	option proto 'static'

config interface 'wg1'
	option proto 'wireguard'
	option ns_type 'server'
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
    """Replace `wgauth._run`: answer nft and wg like the firewall would."""

    def __init__(self, table=None, handshakes="", endpoints=""):
        self.table = table
        self.handshakes = handshakes
        self.endpoints = endpoints
        self.calls = []

    def __call__(self, cmd, input=None):
        self.calls.append((cmd, input))
        if cmd[:3] == ["nft", "-j", "list"]:
            if self.table is None:
                return subprocess.CompletedProcess(cmd, 1, "", "Error: No such file or directory")
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"nftables": self.table}), "")
        if cmd == ["wg", "show", "all", "latest-handshakes"]:
            return subprocess.CompletedProcess(cmd, 0, self.handshakes, "")
        if cmd == ["wg", "show", "all", "endpoints"]:
            return subprocess.CompletedProcess(cmd, 0, self.endpoints, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def scripts(self):
        return [script for cmd, script in self.calls if cmd == ["nft", "-f", "-"]]

    def commands(self, name):
        return [cmd for cmd, _ in self.calls if cmd[0] == name]


def table_objects(servers, sessions=None):
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
    counts = {"input": 1 + 2 * len(servers), "forward": 5 * len(servers), "unauth_input": 4}
    for chain, count in counts.items():
        objects.append({"chain": {"family": "inet", "table": "ns_wgauth", "name": chain}})
        for _ in range(count):
            objects.append({"rule": {"family": "inet", "table": "ns_wgauth", "chain": chain, "expr": []}})
    return objects


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    path = tmp_path.joinpath("run")
    monkeypatch.setattr(wgauth, "RUN_DIR", path.as_posix())
    monkeypatch.setattr(wgauth, "SESSIONS_FILE", path.joinpath("sessions.json").as_posix())
    monkeypatch.setattr(wgauth, "LOCK_FILE", path.joinpath("lock").as_posix())
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
    assert wgauth.get_lock_endpoint(u) is True
    u.set("ns-wgauth", "config", "lock_endpoint", "0")
    assert wgauth.get_lock_endpoint(u) is False
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


def test_find_peer(tmp_path):
    u = _setup_db(tmp_path)
    assert wgauth.find_peer(u, "10.103.1.2") == ("wg1", "wg1_ns_aaaaaaaa_peer")
    # disabled peer
    assert wgauth.find_peer(u, "10.103.1.3") == (None, None)
    # server without login
    assert wgauth.find_peer(u, "10.103.2.2") == (None, None)
    # disabled server
    assert wgauth.find_peer(u, "10.103.4.2") == (None, None)
    assert wgauth.find_peer(u, "192.168.1.10") == (None, None)


def test_get_peer_user(tmp_path):
    u = _setup_db(tmp_path)
    assert wgauth.get_peer_user(u, "wg1", "wg1_ns_aaaaaaaa_peer")["id"] == "ns_wgalice"
    # the user doesn't exist
    assert wgauth.get_peer_user(u, "wg1", "wg1_ns_bbbbbbbb_peer") is None
    # no user linked
    assert wgauth.get_peer_user(u, "wg1", "wg1_ns_eeeeeeee_peer") is None
    # only local databases
    u.set("network", "wg1", "ns_user_db", "wgauth_ldap")
    assert wgauth.get_peer_user(u, "wg1", "wg1_ns_aaaaaaaa_peer") is None


def test_check_credentials(tmp_path):
    u = _setup_db(tmp_path)
    peer = "wg1_ns_aaaaaaaa_peer"
    assert wgauth.check_credentials(u, "wg1", peer, "alice", PASSWORD)["name"] == "alice"
    assert wgauth.check_credentials(u, "wg1", peer, "ALICE", PASSWORD)["name"] == "alice"
    assert wgauth.check_credentials(u, "wg1", peer, "alice", "wrong") is None
    assert wgauth.check_credentials(u, "wg1", peer, "alice", "") is None
    assert wgauth.check_credentials(u, "wg1", peer, "alice", None) is None
    # the user must be the one linked to the peer
    assert wgauth.check_credentials(u, "wg1", peer, "carol", PASSWORD) is None
    # a user without password can't log in
    u.set("network", peer, "ns_user", "carol")
    assert wgauth.check_credentials(u, "wg1", peer, "carol", "") is None


def test_check_credentials_otp(tmp_path):
    u = _setup_db(tmp_path)
    peer = "wg1_ns_aaaaaaaa_peer"
    u.set("network", "wg1", "ns_auth_mode", "key_password_otp")
    code = pyotp.TOTP(OTP_SECRET).now()
    assert wgauth.check_credentials(u, "wg1", peer, "alice", PASSWORD) is None
    assert (
        wgauth.check_credentials(u, "wg1", peer, "alice", PASSWORD, "000000" if code != "000000" else "111111") is None
    )
    assert wgauth.check_credentials(u, "wg1", peer, "alice", PASSWORD, "12345") is None
    assert wgauth.check_credentials(u, "wg1", peer, "alice", PASSWORD, code)["name"] == "alice"
    assert wgauth.check_credentials(u, "wg1", peer, "alice", "wrong", code) is None


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


def test_table_matches():
    assert wgauth.table_matches(table_objects(["wg1", "wg4"]), ["wg1", "wg4"])
    assert not wgauth.table_matches(table_objects(["wg1"]), ["wg1", "wg4"])
    assert not wgauth.table_matches([], ["wg1"])
    broken = [item for item in table_objects(["wg1"]) if item.get("rule", {}).get("chain") != "forward"]
    assert not wgauth.table_matches(broken, ["wg1"])


def test_parse_sessions():
    objects = table_objects(["wg1", "wg4"], {"wg1": {"10.103.1.2": 100, "10.103.1.4": 5}})
    # plain elements, without timeout
    objects.append({"set": {"name": "auth_wg9", "elem": ["10.103.9.2"]}})
    assert wgauth.parse_sessions(objects) == {
        "wg1": {"10.103.1.2": 100, "10.103.1.4": 5},
        "wg4": {},
        "wg9": {"10.103.9.2": 0},
    }


def test_apply_ruleset(tmp_path, mocker):
    u = _setup_db(tmp_path)
    fake = FakeCommands(table=None)
    mocker.patch("nethsec.wgauth._run", fake)
    assert wgauth.apply_ruleset(u) == ["wg1", "wg4", "wg5"]
    assert fake.scripts() == [wgauth.build_ruleset(["wg1", "wg4", "wg5"], 9443)]
    # complete table, nothing to do unless forced
    fake = FakeCommands(table=table_objects(["wg1", "wg4", "wg5"]))
    mocker.patch("nethsec.wgauth._run", fake)
    wgauth.apply_ruleset(u, force=False)
    assert fake.scripts() == []
    wgauth.apply_ruleset(u, force=True)
    assert len(fake.scripts()) == 1


def test_apply_ruleset_removes_old_sets(tmp_path, mocker):
    u = _setup_db(tmp_path)
    fake = FakeCommands(table=table_objects(["wg1", "wg2", "wg4", "wg5"]))
    mocker.patch("nethsec.wgauth._run", fake)
    wgauth.apply_ruleset(u, force=False)
    assert ["nft", "delete", "set", "inet", "ns_wgauth", "auth_wg2"] in fake.commands("nft")


def test_apply_ruleset_without_gated_servers(tmp_path, mocker):
    u = _setup_db(tmp_path)
    for server in ("wg1", "wg4", "wg5"):
        u.set("network", server, "ns_auth_mode", "key")
    fake = FakeCommands(table=table_objects(["wg1"]))
    mocker.patch("nethsec.wgauth._run", fake)
    assert wgauth.apply_ruleset(u) == []
    assert fake.scripts() == ["delete table inet ns_wgauth\n"]
    fake = FakeCommands(table=None)
    mocker.patch("nethsec.wgauth._run", fake)
    wgauth.apply_ruleset(u)
    assert fake.scripts() == []


def test_apply_ruleset_failure(tmp_path, mocker):
    u = _setup_db(tmp_path)

    def failing(cmd, input=None):
        if cmd == ["nft", "-f", "-"]:
            return subprocess.CompletedProcess(cmd, 1, "", "Error: syntax error")
        return subprocess.CompletedProcess(cmd, 1, "", "")

    mocker.patch("nethsec.wgauth._run", failing)
    with pytest.raises(RuntimeError):
        wgauth.apply_ruleset(u)


def test_open_and_close_session(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    fake = FakeCommands(table=table_objects(["wg1", "wg4", "wg5"]), endpoints="wg1\tKEY_ALICE\t203.0.113.7:40001\n")
    mocker.patch("nethsec.wgauth._run", fake)
    mocker.patch("nethsec.wgauth.log")
    alice = wgauth.check_credentials(u, "wg1", "wg1_ns_aaaaaaaa_peer", "alice", PASSWORD)
    expires = wgauth.open_session(u, "wg1", "wg1_ns_aaaaaaaa_peer", "10.103.1.2", alice)
    assert expires - time.time() == pytest.approx(3600, abs=5)
    assert fake.scripts()[-1].splitlines() == [
        "add element inet ns_wgauth auth_wg1 { 10.103.1.2 }",
        "delete element inet ns_wgauth auth_wg1 { 10.103.1.2 }",
        "add element inet ns_wgauth auth_wg1 { 10.103.1.2 timeout 3600s }",
    ]
    entry = wgauth.load_metadata()["wg1"]["10.103.1.2"]
    assert entry["peer"] == "wg1_ns_aaaaaaaa_peer"
    assert entry["user"] == "alice"
    assert entry["fingerprint"] == wgauth.user_fingerprint(u, "wg1", alice)
    # the public IP of the client, without the port
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
    u = _setup_db(tmp_path)
    mocker.patch("nethsec.wgauth._run", FakeCommands(table=table_objects(["wg1"])))
    with pytest.raises(ValueError):
        wgauth.open_session(u, "wg1", "wg1_ns_aaaaaaaa_peer", "10.103.1.2 }; flush ruleset", {"name": "alice"})


def _session(u, peer="wg1_ns_aaaaaaaa_peer", user="alice"):
    alice = users.get_user_by_name(u, "alice", "wgauth_users")
    return {"peer": peer, "user": user, "fingerprint": wgauth.user_fingerprint(u, "wg1", alice)}


def test_session_problem(tmp_path):
    u = _setup_db(tmp_path)
    now = int(time.time())
    gated = wgauth.list_gated_servers(u)
    entry = _session(u)
    fresh = {"KEY_ALICE": now - 30}

    def problem(server="wg1", address="10.103.1.2", entry=entry, handshakes=fresh, idle=300):
        return wgauth.session_problem(u, server, address, entry, handshakes, now, idle, gated)

    assert problem() is None
    assert problem(entry=None) == "unknown_session"
    assert problem(server="wg2") == "server_changed"
    assert problem(address="10.103.1.9") == "peer_changed"
    assert problem(entry=_session(u, peer="wg1_ns_bbbbbbbb_peer")) == "peer_changed"
    assert problem(entry=_session(u, user="carol")) == "user_changed"
    assert problem(handshakes={"KEY_ALICE": now - 600}) == "disconnected"
    assert problem(handshakes={}) == "disconnected"
    # without handshake information, or with the check disabled, the session stays
    assert problem(handshakes=None) is None
    assert problem(handshakes={}, idle=0) is None

    u.set("users", "ns_wgalice", "password", users.shadow_password("new password"))
    assert problem() == "user_changed"


def test_session_problem_server_and_peer_disabled(tmp_path):
    u = _setup_db(tmp_path)
    now = int(time.time())
    gated = wgauth.list_gated_servers(u)
    entry = _session(u)
    u.set("network", "wg1_ns_aaaaaaaa_peer", "disabled", "1")
    assert wgauth.session_problem(u, "wg1", "10.103.1.2", entry, None, now, 300, gated) == "peer_changed"
    u.set("network", "wg1_ns_aaaaaaaa_peer", "disabled", "0")
    u.set("network", "wg1", "disabled", "1")
    assert wgauth.session_problem(u, "wg1", "10.103.1.2", entry, None, now, 300, gated) == "server_changed"


def test_endpoints(mocker):
    assert wgauth.endpoint_address("203.0.113.7:51820") == "203.0.113.7"
    assert wgauth.endpoint_address("[2001:db8::1]:51820") == "2001:db8::1"
    fake = FakeCommands(endpoints="wg1\tKEY_A\t203.0.113.7:51820\nwg1\tKEY_B\t(none)\nwg2\tKEY_C\t[2001:db8::1]:4500\n")
    mocker.patch("nethsec.wgauth._run", fake)
    assert wgauth.read_endpoints() == {"KEY_A": "203.0.113.7", "KEY_C": "2001:db8::1"}


def test_session_problem_endpoint(tmp_path):
    u = _setup_db(tmp_path)
    now = int(time.time())
    gated = wgauth.list_gated_servers(u)
    entry = dict(_session(u), endpoint="203.0.113.7")

    def problem(endpoints):
        return wgauth.session_problem(u, "wg1", "10.103.1.2", entry, None, now, 300, gated, endpoints)

    assert problem({"KEY_ALICE": "203.0.113.7"}) is None
    # a copy of the configuration used from another network
    assert problem({"KEY_ALICE": "198.51.100.20"}) == "endpoint_changed"
    # unknown endpoint, for example after an interface restart
    assert problem({}) is None
    # check disabled
    assert problem(None) is None
    # endpoint not recorded at login
    entry.pop("endpoint")
    assert problem({"KEY_ALICE": "198.51.100.20"}) is None


def test_reconcile_endpoint(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    now = int(time.time())
    fake = FakeCommands(
        table=table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3000}}),
        handshakes=f"wg1\tKEY_ALICE\t{now - 10}\n",
        endpoints="wg1\tKEY_ALICE\t203.0.113.7:40001\n",
    )
    mocker.patch("nethsec.wgauth._run", fake)
    log = mocker.patch("nethsec.wgauth.log")
    # the endpoint wasn't known at login: recorded now
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(u)}})
    assert wgauth.reconcile(u) == []
    assert wgauth.load_metadata()["wg1"]["10.103.1.2"]["endpoint"] == "203.0.113.7"
    # the same key from another public IP ends the session
    fake.endpoints = "wg1\tKEY_ALICE\t198.51.100.20:51820\n"
    assert wgauth.reconcile(u) == [("wg1", "10.103.1.2", "endpoint_changed")]
    assert any("from 203.0.113.7, now 198.51.100.20" in call.args[0] for call in log.call_args_list)
    # the lock can be disabled
    wgauth.save_metadata({"wg1": {"10.103.1.2": dict(_session(u), endpoint="203.0.113.7")}})
    u.set("ns-wgauth", "config", "lock_endpoint", "0")
    assert wgauth.reconcile(u) == []


def test_session_survives_interface_restart(tmp_path):
    u = _setup_db(tmp_path)
    now = int(time.time())
    gated = wgauth.list_gated_servers(u)
    entry = dict(_session(u), login=now - 3600, seen=now - 100)
    # the interface restarted: no handshake yet, but the latest one seen is recent
    assert wgauth.session_problem(u, "wg1", "10.103.1.2", entry, {}, now, 300, gated) is None
    entry["seen"] = now - 400
    assert wgauth.session_problem(u, "wg1", "10.103.1.2", entry, {}, now, 300, gated) == "disconnected"
    # a recent login counts as a handshake
    entry = dict(_session(u), login=now - 10)
    assert wgauth.session_problem(u, "wg1", "10.103.1.2", entry, {}, now, 300, gated) is None
    # corrupted metadata counts as no handshake
    entry = dict(_session(u), login="yesterday", seen=True)
    assert wgauth.session_problem(u, "wg1", "10.103.1.2", entry, {}, now, 300, gated) == "disconnected"


def test_reconcile(tmp_path, mocker, run_dir):
    u = _setup_db(tmp_path)
    now = int(time.time())
    fake = FakeCommands(
        table=table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3000, "10.103.1.9": 3000}}),
        handshakes=f"wg1\tKEY_ALICE\t{now - 10}\nwg1\tKEY_BOB\t0\n",
    )
    mocker.patch("nethsec.wgauth._run", fake)
    mocker.patch("nethsec.wgauth.log")
    wgauth.save_metadata({"wg1": {"10.103.1.2": _session(u), "10.103.1.7": _session(u)}})
    ended = wgauth.reconcile(u)
    assert sorted(ended) == [("wg1", "10.103.1.7", "expired"), ("wg1", "10.103.1.9", "unknown_session")]
    assert list(wgauth.load_metadata()["wg1"]) == ["10.103.1.2"]
    # the latest handshake is remembered
    assert wgauth.load_metadata()["wg1"]["10.103.1.2"]["seen"] == now - 10
    # the interface restarted: the handshakes are gone, the session stays
    fake.handshakes = ""
    fake.table = table_objects(["wg1", "wg4", "wg5"], {"wg1": {"10.103.1.2": 3000}})
    assert wgauth.reconcile(u) == []
    # the idle check uses the configured timeout
    wgauth.save_metadata({"wg1": {"10.103.1.2": dict(_session(u), seen=now - 200)}})
    fake.handshakes = f"wg1\tKEY_ALICE\t{now - 200}\n"
    assert wgauth.reconcile(u) == [("wg1", "10.103.1.2", "disconnected")]
    assert wgauth.load_metadata() == {}
