---
layout: default
title: WireGuard user authentication
parent: Design
---

# WireGuard user authentication

**Status:** implemented in the [ns-wgauth](../../packages/ns-wgauth/) package, not released yet.

* TOC
{:toc}

## Summary

A WireGuard server can require its users to log in with the username and password of a local users database,
the same kind of database used by OpenVPN Road Warrior, optionally followed by an OTP code.

The WireGuard key still opens the tunnel. Until the user logs in, the firewall lets the peer reach only a login
page on the firewall itself. After a successful login, the peer's VPN address is allowed for a limited time.
The user proves two things: they have the key, and they know the password.

Servers keep working as before unless the administrator enables the login.

## Why WireGuard needs a separate login step

WireGuard authenticates peers only by their keys: the handshake checks the peer's public key and the optional
pre-shared key. Unlike OpenVPN, where `auth-user-pass-verify` runs `openvpn-local-auth` during the connection,
there is no point in the handshake where the firewall can ask for a username and a password.

So the password check happens after the tunnel is up, and the firewall enforces its result with nftables.

## Goals

- check username, password and optionally an OTP code against a local users database
- work with the standard WireGuard apps (Windows, macOS, Linux, Android, iOS)
- expose nothing new on the WAN
- keep sessions across firewall reloads and WireGuard interface restarts
- no behavior change for existing servers
- no new packages in the image besides `ns-wgauth` itself

Not covered:

- LDAP databases: possible later, see [Future work](#future-work)
- site-to-site peers and WireGuard client tunnels (`ns_type 'tunnel'`)
- a password prompt inside the WireGuard app, which needs a custom client, see [Clients](#clients)

## User experience

1. The administrator links each peer to a user and gives the user the peer configuration, as before.
   The configuration contains the login address as a comment.
2. The user activates the tunnel in the WireGuard app.
3. The user opens the login page, for example `http://10.103.1.1:8181/`, and enters username, password and,
   if required, the OTP code. Until then only the login page answers: everything else is rejected.
4. After the login the traffic flows. The page shows when the session expires and has a log-out button.
5. The session ends when it expires (8 hours by default), when the peer doesn't handshake for 5 minutes,
   when the peer shows up from another public IP, when the user logs out, or when the administrator changes the
   peer, the user or the server. The user then logs in again.

## Clients

No new client is needed. The tunnel itself doesn't change, so every standard WireGuard app connects as before,
and the login is an ordinary web page reached through the tunnel. The generated peer configuration gets one
comment line, ignored by the apps:

```
# Login = http://10.103.1.1:8181/
```

The trade-off is that the app can't ask for credentials:

- the user must open the page after connecting
- when the session expires, the app still shows the tunnel as connected while the traffic is rejected
- a phone that stops sending keepalives while asleep is logged out after the idle timeout

A companion app that opens the page when the tunnel comes up, or a full client with its own login like the
defguard client, would remove this step. It is optional and can be built later on top of this design.

## Configuration

### Server

Options of the WireGuard server interface (`network.wg<N>` with `ns_type 'server'`):

- `ns_auth_mode`: `key` (the default when the option is missing), `key_password`, `key_password_otp`
- `ns_user_db`: the users database; required unless `ns_auth_mode` is `key`, and it must be a local database
- `ns_auth_timeout`: session length in seconds, default `28800` (8 hours), from 300 to 604800

A server is *gated* when its `ns_auth_mode` isn't `key`. Any other value gates the server, an unknown one too:
a typo must not open the gate.

`ns_user_db` is the option name used by OpenVPN, and `users.used_by()` in python3-nethsec already looks for it in
`network` sections: the users page reports the database as used by WireGuard.

The peers of a gated server can't have remote networks (`ns_routes`): the firewall identifies a peer by its reserved
IP, so the traffic of the networks behind a peer would be blocked, and a peer routing whole networks is a site-to-site
peer, not a person. A server with such peers can't become gated.

### Peer

Option of the peer section (`network.wg<N>_<id>_peer`):

- `ns_user`: the user name in the server's `ns_user_db`, required on a gated server

The link lives on the peer, so a user can have several peers, one per device, on one or more servers.
Each peer logs in separately. A peer without a user, or linked to a user that doesn't exist anymore, can't log in.

### Users

No new options. With `key_password_otp` the OTP secret is the user's `openvpn_2fa` option, the one used by
OpenVPN Road Warrior: a user already enrolled for OpenVPN uses the same authenticator entry.
If the user has no secret yet, `ns.wireguard` creates it when the user is linked to a peer of a server that requires
OTP, or when a server starts requiring it.

### Login service

`/etc/config/ns-wgauth`:

```
config main 'config'
	option port '8181'
	option idle_timeout '300'
	option lock_endpoint '1'
	option max_failures '5'
	option lockout_time '900'
```

## Architecture

```
WireGuard client                      Firewall
----------------                      --------
tunnel up (key)  ───────────────────► wg1 ──► table inet ns_wgauth
                                              10.103.1.5 not in @auth_wg1:
                                              only login page and ping to the firewall

browser: POST /api/login  ──────────► nginx :8181 ──► ns-wgauth (unix socket)
                                              source IP → peer → linked user
                                              check password (and OTP)
                                              add 10.103.1.5 to @auth_wg1, timeout 8h

traffic  ───────────────────────────► wg1 ──► accepted here, fw4 zone rules apply as usual
```

Components:

- `table inet ns_wgauth`: an nftables table owned by the feature, with one set of logged-in addresses
  per gated server and the chains enforcing it
- an nginx server block on the login port (`/etc/nginx/conf.d/ns-wgauth.conf`): it serves the static page from
  `/www-wgauth` and proxies `/api/` to the daemon, adding request size limits and rate limiting (`limit_req`)
- the `ns-wgauth` daemon (`ns-wgauth serve`, Python, on `/var/run/ns-wgauth.sock`): it checks credentials, adds
  and removes set elements, and every 15 seconds ends the sessions that are no longer valid
- `ns-wgauth sync`: it builds the table and the nginx server from UCI, keeping the sessions that are still valid
- `nethsec.wgauth` in python3-nethsec: the logic shared by the daemon and the `ns.wireguard` API

### Why a separate nftables table

fw4 rebuilds its `inet fw4` table on every reload, and commits from the UI reload it often. A set inside fw4,
for example through `/usr/share/nftables.d/table-pre` as ns-dpi does, would be emptied each time and every user
would be logged out. `fw4 start`, `reload`, `restart` and `stop` touch only `inet fw4`; banIP (threat shield)
relies on this with its own `table inet banIP`. Only `fw4 flush` deletes every table, see
[Failing closed](#failing-closed).

### Rules

`ns-wgauth sync` generates the table from the gated servers, enabled or not. With one gated server `wg1` and the
login port 8181:

```
table inet ns_wgauth {
	set gated {
		type ifname
		elements = { "wg1" }
	}

	set auth_wg1 {
		type ipv4_addr
		flags timeout
	}

	chain input {
		type filter hook input priority filter - 1; policy accept;
		iifname != @gated iifname != "lo" tcp dport 8181 drop
		iifname "wg1" meta nfproto ipv6 drop
		iifname "wg1" ip saddr != @auth_wg1 jump unauth_input
	}

	chain forward {
		type filter hook forward priority filter - 1; policy accept;
		iifname "wg1" meta nfproto ipv6 drop
		iifname "wg1" ip saddr != @auth_wg1 meta l4proto tcp reject with tcp reset
		iifname "wg1" ip saddr != @auth_wg1 reject with icmpx type admin-prohibited
		oifname "wg1" meta nfproto ipv6 drop
		oifname "wg1" ip daddr != @auth_wg1 drop
	}

	chain unauth_input {
		tcp dport 8181 accept
		icmp type echo-request accept
		meta l4proto tcp reject with tcp reset
		reject with icmpx type admin-prohibited
	}
}
```

- The chains run just before fw4 (`priority filter - 1`). A drop or a reject here is final, while an accept only
  lets the packet go on to fw4: the zone rules still apply to logged-in users.
- `sync` adds the sets and replaces the rules in one `nft -f` transaction: the sets, and so the sessions, survive.
- The source address identifies the peer. WireGuard drops packets whose source isn't in the allowed IPs of the
  peer that sent them, and on a gated server the allowed IPs of a peer are only its reserved address:
  a peer can't use the address of another peer.
- The check runs on every packet, not only on new connections. When a session ends, the daemon also deletes the
  conntrack entries of the peer, so connections offloaded to a flowtable stop too.
- The `oifname` rule blocks connections from the LAN to peers that aren't logged in.
- The login port is reachable only from gated WireGuard interfaces, never from LAN or WAN, whatever fw4 allows.
- WireGuard server networks are IPv4 only: IPv6 coming from a gated interface is dropped.
- Rejecting with a TCP reset makes browsers and apps fail at once instead of waiting.
- Before the login there is no DNS, not even to the firewall: its resolver forwards queries to the internet, so a
  copied configuration could tunnel data through it. The login page is opened by IP.
- With no gated server the table is removed.

### Sessions

- Login: the daemon adds the peer's address to the server's set with the `ns_auth_timeout` timeout.
  A new login replaces the element and restarts the timer.
- What the firewall knows about each session is in `/var/run/ns-wgauth/sessions.json`: peer, user, login time,
  public IP of the client at login, latest handshake seen and a fingerprint of the credentials (authentication mode, database, user name, password
  hash and, with OTP, the secret). A file lock serializes the daemon and the `sync` command.
- Expiry: nftables removes the element when the timeout ends; the next check forgets its metadata.
- Every 15 seconds, and on every `sync`, the sessions are checked. A session ends when:
  - its metadata is missing
  - the server is disabled or doesn't require the login anymore
  - the peer is disabled, removed, linked to another user, or has another reserved IP
  - the user is removed, or its fingerprint changed (for example a new password)
  - the peer's latest handshake is older than `idle_timeout` (`wg show all latest-handshakes`). The generated
    configurations set `PersistentKeepalive = 25`, so a connected client renews its handshake about every
    2 minutes even when idle. The check remembers the latest handshake it has seen: a commit that touches a
    server restarts its interface (`restart-wireguard.py`) and resets the handshakes, and that must not end the
    sessions of its peers
  - with `lock_endpoint` (the default), the peer sends from another public IP than at login
    (`wg show all endpoints`, the port is ignored), see [Copied configurations](#copied-configurations)
- Logout: from the login page, or by the administrator with `ns.wireguard logout-peer` or `ns-wgauth logout`.
- Sessions live only in kernel memory and in `/var/run`: a reboot or an HA failover logs everyone out.

### Login API

nginx serves it at `http://<server address>:<port>/api/` and proxies it to the daemon, adding `X-Real-IP` (the
client address) and `X-Forwarded-Host` (the requested host).

- `GET /api/status`: `{"authenticated": false, "otp_required": true, "server": "Road warriors"}`; with a session
  also `"user"` and `"expires"`
- `POST /api/login` with `{"username": "alice", "password": "...", "otp": "123456"}`:
  `{"result": "success", "user": "alice", "expires": "2026-10-24T18:00:00+00:00"}`
- `POST /api/logout` with `{}`: `{"result": "success"}`

Every request must come from the reserved IP of an enabled peer on an enabled gated server, and must be addressed to
the server's address: a page of another site whose name resolves to that address (DNS rebinding) gets
`403 {"error": "forbidden"}`. `login` and `logout` accept only `Content-Type: application/json`: a form on another
site can't send it without a CORS preflight, which the API never answers.

The login checks:

1. the peer isn't locked out: after `max_failures` failures it gets `429 {"error": "too_many_attempts"}` for
   `lockout_time` seconds; nginx also limits the login requests per address
2. the username matches the peer's `ns_user`, case insensitive like `users.get_user_by_name()`
3. the user exists in `ns_user_db` and `users.check_password()` accepts the password
4. with `key_password_otp`, the TOTP code is valid (`pyotp`, accepting the previous and next 30 seconds) and wasn't
   already used by this user in the last 2 minutes

Every failed check returns the same `401 {"error": "invalid_credentials"}`, so the page doesn't tell which one
failed. Logins, failures and logouts are written to syslog (`/var/log/messages`) with the `ns-wgauth` tag.

The password goes over plain HTTP inside the WireGuard tunnel: WireGuard already encrypts and authenticates
the traffic between the client and the firewall, and the port can't be reached from other interfaces.
HTTPS would show a certificate warning (the firewall certificate doesn't match the tunnel address) without
adding protection. Browsers may still label the page as "Not secure". The page sets a strict content security
policy and forbids framing.

### Failing closed

The gate is a set of drop rules: if the `ns_wgauth` table were missing, gated peers would get full access.
To avoid it:

- the init script starts before the network (`START=15`) and runs `ns-wgauth sync` before starting the daemon,
  so the table exists before any WireGuard interface comes up. If the daemon then fails, users can't log in,
  but nobody gets through without logging in
- the table keeps gating disabled servers too: enabling a server never opens a window without the gate
- every 15 seconds the daemon checks the table and rebuilds it if it's missing or incomplete, for example after
  `fw4 flush`; the sessions are then lost and users log in again
- `ns.wireguard list-servers` reports `auth_enforced: false` when a server requires the login but its set is
  missing, so the UI can warn the administrator

The init script registers procd reload triggers on the `network`, `users` and `ns-wgauth` configurations:
any commit that adds a server, changes a peer or a password runs `sync` again. Starting the daemon is also decided
there: it runs only while a server requires the login.

## Copied configurations

The goal is that a leaked or copied peer configuration alone doesn't give access to the VPN.

- **The configuration alone**: the copy completes the WireGuard handshake, because the key is valid, but reaches
  only the login page and ping. Without the username, the password and, with `key_password_otp`, the OTP code of the
  linked user, it gets nothing else. Wrong attempts lock the peer out (`max_failures`, `lockout_time`), nginx limits
  the login requests, and every failure is logged. The page doesn't tell the username.
- **The configuration used while the user is logged in**: WireGuard can't tell apart two devices with the same key,
  and the session belongs to the key. With `lock_endpoint`, the session is bound to the public IP the client had at
  login: when the copy sends from another network the session ends within 15 seconds and a
  `possible copy of the configuration` warning is logged. The legitimate user must log in again; while both devices
  are active, neither keeps a session.
- **Limits of the lock**: two devices behind the same public IP (the same office or home network) can't be told
  apart. A user who changes network, for example from Wi-Fi to 4G, logs in again.
- **Configuration, password and OTP secret leaked together** defeat the login: deliver them through different
  channels, and enroll the OTP in person or over a screen share.

Defguard closes the second case differently: its desktop client receives a new preshared key after every MFA
login, so a copy without that key can't even complete the handshake. That needs a custom client, which this design
avoids.

The firewall keeps the private keys of the peers, in its configuration and in its backups, as before this feature.

### Behind NAT

The firewall can sit behind a router that forwards the WireGuard UDP port to it, with a single network card:

- only the WireGuard port is forwarded: the login page is reached through the tunnel
- the endpoints seen by the firewall must be the public IPs of the clients (check with `wg show wg1 endpoints`).
  A port forward keeps them; if the router also masquerades the forwarded traffic, every client shows the router
  address, and `lock_endpoint` must be disabled because it can't tell clients apart
- the traffic from the LAN back to the VPN clients needs a route on the router or masquerading on the firewall,
  as for any VPN on such a firewall

## API changes

### ns.wireguard

- `add-server`, `edit-server`: new optional parameters `auth_mode` (default `key`), `user_db`, `auth_timeout`.
  Validation errors: `auth_mode` `invalid`, `peers_with_remote_networks`; `user_db` `required`, `db_not_found`,
  `db_not_local`; `auth_timeout` `invalid`. On `edit-server`, missing login options keep their current values:
  a client that doesn't know them, like an older UI, can't turn the login off.
- `add-peer`, `edit-peer`: new parameter `user`, required on gated servers; on edit, a missing `user` keeps the
  current one. Validation errors: `user` `required`, `user_not_found`; `remote_networks` `not_allowed`.
- `list-servers`: servers also return `auth_mode`, `user_db`, `auth_timeout`, `login_url` and `auth_enforced`;
  peers also return `user`, `authenticated` and `auth_expires`.
- new `logout-peer` (`{"id": "wg1_ns_1234abcd_peer"}`): ends the peer's session. It changes no UCI option,
  so there is nothing to commit.
- new `download-peer-2fa` (`{"id": "wg1_ns_1234abcd_peer"}`): returns the OTP QR code of the linked user as SVG,
  like `ns.ovpnrw download-user-2fa`.
- the peer configuration gets the `# Login = ...` comment on gated servers.

The ACL `ns.wireguard.json` already allows every method of `ns.wireguard`.

### ns.users

No changes. Deleting a user, or changing its password, ends its sessions at the next `sync`, run by the procd
trigger on the `users` configuration. The peers linked to a deleted user stay, but can't log in until they are
linked to another user.

## Packaging

The `ns-wgauth` package (`PKGARCH:=all`), enabled by `config/ns-wgauth.conf`:

- `/usr/sbin/ns-wgauth`: the daemon and the `sync`, `needed`, `status` and `logout` commands
- `/etc/init.d/ns-wgauth`: `START=15`, procd reload triggers, the daemon only while a server is gated
- `/etc/config/ns-wgauth`
- `/www-wgauth/`: the login page, plain HTML, CSS and JavaScript without inline code
- `/etc/nginx/conf.d/ns-wgauth.conf`: generated by `sync`. A configuration that `nginx -t` refuses is reverted,
  because the same nginx serves the administration UI

All the dependencies are already in the image: `python3-nethsec`, `python3-pyotp` (required by `ns-openvpn`),
`wireguard-tools` (required by `ns-api`), `nginx-ssl`, `nftables-json`, `conntrack` and `qrencode`. The image
grows by a few scripts and a static page; at runtime it adds one Python process, only while a server is gated.

## High availability

`ns-ha-export` copies the whole WireGuard interface and peer sections, so the new options reach the backup node
with no change, and `/etc/config/ns-wgauth` is synchronized as a configuration file. The backup node runs
`ns-wgauth` as well, while its WireGuard interfaces stay disabled until a failover. Sessions aren't synchronized:
after a failover users log in again.

## Upgrades and downgrades

- Existing servers have no `ns_auth_mode`, so they behave as `key` and nothing changes.
- Servers created with the WireGuard API before the UI rewrite may still have `ns_user_db`:
  `wireguard-migrate.py` doesn't remove it. The gate depends on `ns_auth_mode`, not on `ns_user_db`,
  so those servers aren't affected.
- **A downgrade fails open.** An image without the feature ignores the new options and has no gate:
  gated servers accept every peer with a valid key, without a login. Before downgrading, switch the servers back
  to `key` or disable them. The same applies to an HA pair: both nodes must run a version with the feature.
  Removing the package has the same effect. The administrator manual must state it.

## Controller

The controller connects to the unit through OpenVPN (`ns-plug`), so the gate never applies to it.
The controller manages the unit through the unit's own UI and API, so it needs no change:
units without the feature simply don't show the new fields.

## UI and documentation

In nethsecurity-ui:

- server form: authentication mode, users database, session length
- peer form: user picker, required on gated servers; no remote networks on gated servers
- peer list: user, logged-in state, session expiry, log-out action, OTP QR code download
- server card: login page address, warning when `auth_enforced` is `false`

The administrator manual in nethsecurity-docs gets a section about the login, the steps for the users and the
downgrade warning.

## Alternatives considered

- **Sets inside the fw4 table**: simpler rules, but every firewall reload would log everyone out.
- **Add the peer to the interface only after the login** (`wg set wg1 peer ...`): a peer that isn't logged in
  gets no handshake reply at all, but the login page must then be reachable from the WAN, a new public attack
  surface.
- **Derive the private key or the pre-shared key from the password**: anyone who reads the public key
  (UCI, backups, controller) could guess passwords offline, and the firewall stores both keys anyway.
- **A post-commit hook to apply the changes**: hooks run in no fixed order and only for commits made through
  `ns.commit`; procd reload triggers run for every configuration reload.
- **A custom client only**: the best experience, but apps to build and maintain for every platform.
  It can still be added later on top of this design.

## Future work

- LDAP databases, reusing the bind logic of `openvpn-remote-auth`
- redirect plain HTTP from peers that aren't logged in to the login page, like a captive portal
- connection history, like the `connections.db` of OpenVPN Road Warrior
- a companion app that opens the login page when the tunnel comes up

## Open questions

- Keep `openvpn_2fa` as the OTP secret, or move to a generic option name with a migration?
- Defaults: session length (8 hours), idle timeout (5 minutes), login port (8181).
