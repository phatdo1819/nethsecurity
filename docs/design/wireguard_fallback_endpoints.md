---
layout: default
title: WireGuard fallback endpoints
parent: Design
---

# WireGuard fallback endpoints

**Status:** implemented in `ns.wireguard`, not released yet.

* TOC
{:toc}

## Summary

A WireGuard server can have up to 4 fallback endpoints besides its public endpoint: other addresses where the
clients reach it, such as the IP of a second internet connection, or a name of another provider. The clients that
support it try them in order when the public endpoint doesn't answer; the other clients use only the public
endpoint, as before.

## Configuration

The fallback endpoints are the list option `ns_fallback_endpoints` of the server interface, as the administrator
wrote them: a host, IP address or domain name, with an optional port (`vpn2.example.com`, `203.0.113.10:51821`,
`[2001:db8::1]:51820`). Without a port, a fallback endpoint uses the `listen_port` of the server, also when the port
changes later.

```
config interface 'wg1'
	option proto 'wireguard'
	option listen_port '51820'
	option ns_public_endpoint 'vpn.example.com'
	list ns_fallback_endpoints 'vpn2.example.com'
	list ns_fallback_endpoints '203.0.113.10:51821'
```

The firewall doesn't need anything else: WireGuard listens on all the addresses of the firewall, and the rule of
the server accepts its port on any WAN. When the endpoints are on another router, each of them must forward its port
to the firewall.

`add-server` and `edit-server` take them as `fallback_endpoints`; a missing `fallback_endpoints` on `edit-server`
keeps them, so a client that doesn't know the option doesn't remove them. `list-servers` returns them as stored.

## Peer configuration

The configuration of a peer lists them after `Endpoint`, with their port, in a comment:

```
[Peer]
# Name = HQ
PublicKey = ...
AllowedIPs = 10.1.86.0/24
Endpoint = vpn.example.com:51820
# Fallback = vpn2.example.com:51820, 203.0.113.10:51821
PersistentKeepalive = 25
```

The WireGuard format has only one endpoint per peer, and the official apps ignore comments: they keep using
`Endpoint`. A client that reads the comment, like the `# Login` one of the
[user authentication](wireguard_user_auth.md), moves to the next endpoint when the current one doesn't answer its
handshakes, and comes back to the list from the start on the next connection.

IPv6 addresses are written in brackets, `[2001:db8::1]:51820`, the public endpoint too.

## Limits

- The login of [ns-wgauth](wireguard_user_auth.md) isn't affected: it is tied to the public IP of the client, not
  to the endpoint of the server.
- A firewall with more WAN connections answers a client from the address the client used: WireGuard keeps the
  local address of the last packet of each peer. The route of the answer is up to the multi-WAN policies.
