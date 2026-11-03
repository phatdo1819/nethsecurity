import pytest
from euci import EUci

from nethsec import wireguard

# server names nobody else uses: libuci applies the changes that other tests saved in the default savedir
network_db = """
config interface 'wg71'
	option proto 'wireguard'
	option ns_type 'server'
	option ns_network '10.71.0.0/24'

config interface 'wg72'
	option proto 'wireguard'
	option ns_type 'server'
	option ns_network '10.72.0.0/24'

config interface 'wg73'
	option proto 'wireguard'
	option ns_type 'server'
	option ns_network '10.73.0.0/24'

config interface 'wg74'
	option proto 'wireguard'
	option ns_type 'client'
	option ns_network '10.74.0.0/24'
"""

firewall_db = """
config zone 'ns_wg71zone'
	option name 'wg71vpn'
	option forward 'REJECT'

config zone 'ns_wg72zone'
	option name 'wg72vpn'
	option forward 'REJECT'

config zone 'ns_wg73zone'
	option name 'wg73vpn'
	option forward 'REJECT'

config forwarding 'ns_wg71lan'
	option src 'wg71vpn'
	option dest 'lan'
	option ns_link 'network/wg71'
"""


@pytest.fixture
def uci(tmp_path):
    conf_dir = tmp_path.joinpath("config")
    conf_dir.mkdir()
    conf_dir.joinpath("network").write_text(network_db)
    conf_dir.joinpath("firewall").write_text(firewall_db)
    save_dir = tmp_path.joinpath("save")
    save_dir.mkdir()
    return EUci(confdir=conf_dir.as_posix(), savedir=save_dir.as_posix())


def sections(uci, section_type):
    return {name for name in uci.get("firewall") if uci.get("firewall", name) == section_type}


def test_list_servers(uci):
    assert wireguard.list_servers(uci) == ["wg71", "wg72", "wg73"]
    assert wireguard.get_zone("wg71") == "wg71vpn"


def test_nothing_by_default(uci):
    assert wireguard.sync_peer_traffic(uci) == []
    assert not wireguard.allows_client_to_client(uci, "wg71")
    assert wireguard.linked_networks(uci, "wg71") == []


def test_client_to_client(uci):
    uci.set("network", "wg71", "ns_client_to_client", True)
    assert wireguard.allows_client_to_client(uci, "wg71")
    assert wireguard.sync_peer_traffic(uci) == ["ns_wg71_client_to_client"]
    rule = uci.get_all("firewall", "ns_wg71_client_to_client")
    assert uci.get("firewall", "ns_wg71_client_to_client") == "rule"
    assert rule["src"] == "wg71vpn"
    assert rule["dest"] == "wg71vpn"
    # without proto, fw4 would accept only tcp and udp: no ping
    assert rule["proto"] == "all"
    assert rule["target"] == "ACCEPT"
    assert rule["ns_link"] == "network/wg71"
    assert list(rule["ns_tag"]) == ["automated"]
    # again: nothing changes
    assert wireguard.sync_peer_traffic(uci) == []
    # the same server only: no route to add
    assert wireguard.linked_networks(uci, "wg71") == []

    uci.set("network", "wg71", "ns_client_to_client", False)
    assert wireguard.sync_peer_traffic(uci) == ["ns_wg71_client_to_client"]
    assert uci.get("firewall", "ns_wg71_client_to_client", default=None) is None


def test_reachable_servers_one_way(uci):
    uci.set("network", "wg71", "ns_reachable_servers", ["wg72"])
    assert wireguard.get_reachable_servers(uci, "wg71") == ["wg72"]
    assert wireguard.sync_peer_traffic(uci) == ["ns_wg71_to_wg72"]
    forwarding = uci.get_all("firewall", "ns_wg71_to_wg72")
    assert uci.get("firewall", "ns_wg71_to_wg72") == "forwarding"
    assert forwarding["src"] == "wg71vpn"
    assert forwarding["dest"] == "wg72vpn"
    assert forwarding["ns_link"] == "network/wg71"
    # one way: no forwarding back
    assert "ns_wg72_to_wg71" not in sections(uci, "forwarding")
    # but both configurations route the other network: the answers go back through the tunnel
    assert wireguard.linked_networks(uci, "wg71") == ["10.72.0.0/24"]
    assert wireguard.linked_networks(uci, "wg72") == ["10.71.0.0/24"]
    assert wireguard.linked_networks(uci, "wg73") == []
    # the forwardings of add_trusted_zone are left alone
    assert "ns_wg71lan" in sections(uci, "forwarding")


def test_both_ways(uci):
    uci.set("network", "wg71", "ns_reachable_servers", ["wg72", "wg73"])
    uci.set("network", "wg72", "ns_reachable_servers", ["wg71"])
    assert sorted(wireguard.sync_peer_traffic(uci)) == ["ns_wg71_to_wg72", "ns_wg71_to_wg73", "ns_wg72_to_wg71"]
    assert wireguard.linked_servers(uci, "wg71") == ["wg72", "wg73"]
    assert wireguard.linked_networks(uci, "wg71") == ["10.72.0.0/24", "10.73.0.0/24"]
    assert wireguard.linked_networks(uci, "wg72") == ["10.71.0.0/24"]
    assert wireguard.linked_networks(uci, "wg73") == ["10.71.0.0/24"]

    # a server taken off the list loses its forwarding
    uci.set("network", "wg71", "ns_reachable_servers", ["wg73"])
    assert wireguard.sync_peer_traffic(uci) == ["ns_wg71_to_wg72"]
    assert "ns_wg71_to_wg72" not in sections(uci, "forwarding")
    assert {"ns_wg71_to_wg73", "ns_wg72_to_wg71"} <= sections(uci, "forwarding")


def test_invalid_entries_are_ignored(uci):
    # itself, a duplicate, a missing server, a tunnel instead of a server
    uci.set("network", "wg71", "ns_reachable_servers", ["wg71", "wg72", "wg72", "wg99", "wg74"])
    assert wireguard.get_reachable_servers(uci, "wg71") == ["wg72"]
    assert wireguard.sync_peer_traffic(uci) == ["ns_wg71_to_wg72"]


def test_missing_zone(uci):
    uci.delete("firewall", "ns_wg73zone")
    uci.set("network", "wg71", "ns_reachable_servers", ["wg73"])
    uci.set("network", "wg73", "ns_client_to_client", True)
    uci.set("network", "wg73", "ns_reachable_servers", ["wg71"])
    # no section for a zone that doesn't exist: fw4 would refuse it
    assert wireguard.sync_peer_traffic(uci) == []


def test_remove_server(uci):
    uci.set("network", "wg71", "ns_reachable_servers", ["wg72", "wg73"])
    uci.set("network", "wg73", "ns_reachable_servers", ["wg72"])
    uci.set("network", "wg72", "ns_reachable_servers", ["wg71"])
    uci.set("network", "wg72", "ns_client_to_client", True)
    wireguard.sync_peer_traffic(uci)

    # as ns.wireguard delete-server: out of the lists, then the server and its linked sections are deleted
    assert wireguard.remove_server(uci, "wg72") == ["wg71", "wg73"]
    assert list(uci.get("network", "wg71", "ns_reachable_servers", list=True)) == ["wg73"]
    assert uci.get("network", "wg73", "ns_reachable_servers", default=None) is None
    uci.delete("network", "wg72")
    uci.delete("firewall", "ns_wg72zone")
    for section in ("ns_wg72_to_wg71", "ns_wg72_client_to_client"):
        uci.delete("firewall", section)

    assert wireguard.sync_peer_traffic(uci) == ["ns_wg71_to_wg72", "ns_wg73_to_wg72"]
    assert sections(uci, "forwarding") == {"ns_wg71lan", "ns_wg71_to_wg73"}
    assert wireguard.linked_networks(uci, "wg71") == ["10.73.0.0/24"]
