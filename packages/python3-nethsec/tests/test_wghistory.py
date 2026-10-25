import csv
import os

import pytest
from euci import EUci
from nethsec import wghistory

ALICE = "KEY_WGHISTORY_ALICE"
BOB = "KEY_WGHISTORY_BOB"
TUNNEL = "KEY_WGHISTORY_TUNNEL"

network_db = """
config interface 'wg1'
	option proto 'wireguard'
	option ns_type 'server'
	option ns_name 'Road warriors'

config wireguard_wg1 'wg1_ns_wgh0001_peer'
	option ns_name 'Alice laptop'
	option ns_user 'alice'
	option ns_ip '10.103.1.2'
	option public_key 'KEY_WGHISTORY_ALICE'

config wireguard_wg1 'wg1_ns_wgh0002_peer'
	option ns_name 'Bob phone'
	option ns_ip '10.103.1.3'
	option public_key 'KEY_WGHISTORY_BOB'

config interface 'wg2'
	option proto 'wireguard'
	option ns_type 'tunnel'

config wireguard_wg2 'wg2_ns_wgh0003_peer'
	option public_key 'KEY_WGHISTORY_TUNNEL'
"""


@pytest.fixture
def uci(tmp_path):
    conf_dir = tmp_path.joinpath("config")
    conf_dir.mkdir()
    conf_dir.joinpath("network").write_text(network_db)
    conf_dir.joinpath("fstab").write_text("")
    save_dir = tmp_path.joinpath("save")
    save_dir.mkdir()
    return EUci(confdir=conf_dir.as_posix(), savedir=save_dir.as_posix())


@pytest.fixture
def conn(tmp_path):
    conn = wghistory.connect(tmp_path.joinpath("wireguard", "connections.db").as_posix())
    yield conn
    conn.close()


def dump(*peers):
    """`wg show all dump`: (interface, key, endpoint, handshake, rx, tx) for each peer."""
    lines = ["wg1\tPRIVATE\tPUBLIC\t51820\toff"]
    for interface, key, endpoint, handshake, rx, tx in peers:
        lines.append(f"{interface}\t{key}\t(none)\t{endpoint}\t10.103.1.2/32\t{handshake}\t{rx}\t{tx}\t25")
    return "\n".join(lines) + "\n"


def rows(conn):
    return conn.execute(
        "SELECT peer_name, remote_ip_addr, start_time, end_time, bytes_received, bytes_sent FROM connections ORDER BY rowid"
    ).fetchall()


def poll(conn, uci, now, *peers):
    wghistory.record(conn, wghistory.parse_dump(dump(*peers)), wghistory.server_peers(uci), now=now)


def test_parse_dump():
    peers = wghistory.parse_dump(
        dump(
            ("wg1", ALICE, "198.51.100.7:40000", 990, 100, 200),
            ("wg1", BOB, "[2001:db8::7]:40001", 0, 0, 0),
            ("wg1", "NOBODY", "(none)", 0, 0, 0),
        )
    )
    assert peers[("wg1", ALICE)] == {"remote": "198.51.100.7", "handshake": 990, "rx": 100, "tx": 200}
    assert peers[("wg1", BOB)]["remote"] == "2001:db8::7"
    assert peers[("wg1", "NOBODY")]["remote"] == ""
    # the line of the interface isn't a peer
    assert len(peers) == 3


def test_server_peers(uci):
    peers = wghistory.server_peers(uci)
    assert peers[("wg1", ALICE)] == {
        "peer": "wg1_ns_wgh0001_peer",
        "name": "Alice laptop",
        "user": "alice",
        "address": "10.103.1.2",
    }
    assert peers[("wg1", BOB)]["user"] == ""
    # the peers of the client tunnels have no history
    assert ("wg2", TUNNEL) not in peers


def test_connection_lifecycle(uci, conn):
    alice = ("wg1", ALICE, "198.51.100.7:40000")
    poll(conn, uci, 1000, alice + (990, 100, 200), ("wg2", TUNNEL, "203.0.113.1:51820", 995, 5, 5))
    assert rows(conn) == [("Alice laptop", "198.51.100.7", 990, None, 100, 200)]
    poll(conn, uci, 1060, alice + (990, 500, 900))
    # the rekey of WireGuard, without traffic
    poll(conn, uci, 1120, alice + (1110, 500, 900))
    assert rows(conn) == [("Alice laptop", "198.51.100.7", 990, None, 500, 900)]
    # no handshake for 3 minutes: it ended when its counters last moved
    poll(conn, uci, 1300, alice + (1110, 500, 900))
    assert rows(conn) == [("Alice laptop", "198.51.100.7", 990, 1060, 500, 900)]
    poll(conn, uci, 1360, alice + (1110, 500, 900))
    assert len(rows(conn)) == 1
    # back: only the bytes of the new connection
    poll(conn, uci, 2000, alice + (1995, 800, 1000))
    assert rows(conn)[1] == ("Alice laptop", "198.51.100.7", 1995, None, 300, 100)


def test_new_address_new_connection(uci, conn):
    poll(conn, uci, 1000, ("wg1", ALICE, "198.51.100.7:40000", 990, 100, 200))
    poll(conn, uci, 1060, ("wg1", ALICE, "203.0.113.50:5000", 1050, 300, 400))
    assert rows(conn) == [
        ("Alice laptop", "198.51.100.7", 990, 1000, 100, 200),
        ("Alice laptop", "203.0.113.50", 1060, None, 200, 200),
    ]


def test_counters_restart(uci, conn):
    poll(conn, uci, 1000, ("wg1", ALICE, "198.51.100.7:40000", 990, 1000, 2000))
    # the interface restarted, after a change of the configuration
    poll(conn, uci, 1060, ("wg1", ALICE, "198.51.100.7:40000", 1055, 50, 60))
    assert rows(conn) == [
        ("Alice laptop", "198.51.100.7", 990, 1000, 1000, 2000),
        ("Alice laptop", "198.51.100.7", 1055, None, 50, 60),
    ]


def test_peer_gone_and_back(uci, conn):
    poll(conn, uci, 1000, ("wg1", ALICE, "198.51.100.7:40000", 990, 100, 200))
    # the interface is down
    poll(conn, uci, 1060)
    assert rows(conn) == [("Alice laptop", "198.51.100.7", 990, 1000, 100, 200)]
    poll(conn, uci, 1120, ("wg1", ALICE, "198.51.100.7:40000", 1115, 30, 40))
    assert rows(conn)[1] == ("Alice laptop", "198.51.100.7", 1115, None, 30, 40)


def test_recorder_stopped(uci, conn):
    poll(conn, uci, 1000, ("wg1", ALICE, "198.51.100.7:40000", 990, 100, 200))
    # an hour without the recorder: a new connection from the time it runs again
    poll(conn, uci, 4600, ("wg1", ALICE, "198.51.100.7:40000", 4590, 500, 600))
    assert rows(conn) == [
        ("Alice laptop", "198.51.100.7", 990, 1000, 100, 200),
        ("Alice laptop", "198.51.100.7", 4590, None, 400, 400),
    ]


def test_never_connected(uci, conn):
    poll(conn, uci, 1000, ("wg1", BOB, "(none)", 0, 0, 0))
    assert rows(conn) == []


def test_query(uci, conn):
    poll(conn, uci, 1000, ("wg1", ALICE, "198.51.100.7:40000", 990, 100, 200), ("wg1", BOB, "203.0.113.9:1", 995, 7, 8))
    poll(
        conn, uci, 1300, ("wg1", ALICE, "198.51.100.7:40000", 990, 100, 200), ("wg1", BOB, "203.0.113.9:1", 1250, 9, 10)
    )
    poll(
        conn,
        uci,
        2000,
        ("wg1", ALICE, "198.51.100.10:40000", 1990, 150, 260),
        ("wg1", BOB, "203.0.113.9:1", 1250, 9, 10),
    )
    page = wghistory.query(conn, now=2010)
    assert (page["total"], page["results"], page["last_page"]) == (3, 3, 1)
    assert [c["startTime"] for c in page["connections"]] == [1990, 995, 990]
    newest = page["connections"][0]
    assert newest == {
        "instance": "wg1",
        "peer": "wg1_ns_wgh0001_peer",
        "account": "Alice laptop",
        "user": "alice",
        "virtualIpAddress": "10.103.1.2",
        "remoteIpAddress": "198.51.100.10",
        "startTime": 1990,
        "endTime": None,
        "duration": 20,
        "connected": True,
        "bytesReceived": 50,
        "bytesSent": 60,
    }
    assert page["connections"][2]["endTime"] == 1000 and page["connections"][2]["connected"] is False
    assert page["filters"] == {"accounts": ["Alice laptop", "Bob phone"], "instances": ["wg1"]}

    assert [c["startTime"] for c in wghistory.query(conn, accounts=["Alice laptop"], now=2010)["connections"]] == [
        1990,
        990,
    ]
    assert wghistory.query(conn, q="203.0.113", now=2010)["results"] == 1
    assert wghistory.query(conn, q="alice", now=2010)["results"] == 2
    assert wghistory.query(conn, start_time=995, now=2010)["results"] == 2
    assert wghistory.query(conn, instances=["wg9"], now=2010)["results"] == 0
    assert [c["account"] for c in wghistory.query(conn, sort_by="account", desc=False, now=2010)["connections"]] == [
        "Alice laptop",
        "Alice laptop",
        "Bob phone",
    ]
    remote = wghistory.query(conn, sort_by="remoteIpAddress", desc=False, now=2010)["connections"]
    assert [c["remoteIpAddress"] for c in remote] == ["198.51.100.7", "198.51.100.10", "203.0.113.9"]
    # the longest, 305 seconds
    assert wghistory.query(conn, sort_by="duration", now=2010)["connections"][0]["account"] == "Bob phone"
    second = wghistory.query(conn, page=2, per_page=2, now=2010)
    assert (second["last_page"], len(second["connections"])) == (2, 1)
    # not updated for 10 minutes: the recorder stopped, the connection is over
    stale = wghistory.query(conn, now=2700)["connections"][0]
    assert stale["endTime"] == 2000 and stale["connected"] is False and stale["duration"] == 10


def test_empty_history():
    page = wghistory.query(None)
    assert page["connections"] == [] and page["total"] == 0 and page["last_page"] == 1


def test_export_csv(uci, conn, tmp_path):
    poll(conn, uci, 1767225600, ("wg1", ALICE, "198.51.100.7:40000", 1767225590, 100, 200))
    path = tmp_path.joinpath("history.csv")
    wghistory.export_csv(conn, path.as_posix(), "Europe/Rome", {"wg1": "Road warriors"}, now=1767225610)
    with path.open() as fp:
        lines = list(csv.reader(fp))
    assert lines[0][3] == "Started (Europe/Rome)"
    assert lines[1] == [
        "Road warriors",
        "Alice laptop",
        "alice",
        "2026-01-01 00:59:50",
        "",
        "20",
        "10.103.1.2",
        "198.51.100.7",
        "100",
        "200",
    ]
    wghistory.export_csv(None, path.as_posix(), "Not/AZone")
    with path.open() as fp:
        assert next(csv.reader(fp))[3] == "Started (UTC)"


def test_db_path(uci, tmp_path):
    assert wghistory.db_path(uci) == os.path.join("/var", "wireguard", "connections.db")
    storage = tmp_path.joinpath("data")
    storage.mkdir()
    uci.set("fstab", "ns_data", "mount")
    uci.set("fstab", "ns_data", "target", storage.as_posix())
    assert wghistory.db_path(uci) == os.path.join(storage.as_posix(), "wireguard", "connections.db")
    # a storage that isn't mounted
    uci.set("fstab", "ns_data", "target", tmp_path.joinpath("missing").as_posix())
    assert wghistory.db_path(uci) == os.path.join("/var", "wireguard", "connections.db")
