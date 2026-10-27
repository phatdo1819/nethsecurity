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
3. The user opens the login page, for example `http://10.103.1.1:8181/`, from a bookmark or a home-screen icon, or
   opens any plain `http://` address and is redirected there. They enter username, password and, if required, the
   OTP code; the browser can remember the username and password. Until then only the login page answers: everything
   else is rejected.
4. After the login the traffic flows. The page shows when the session expires and has a log-out button.
5. The session ends when it expires (8 hours by default), when the peer doesn't handshake for 5 minutes,
   when the peer shows up from another public IP, when the configuration seems used by two devices, when the user
   logs out, or when the administrator applies a change to the peer, the user or the server. The user then logs in
   again.

## Clients

No new client is needed. The tunnel itself doesn't change, so every standard WireGuard app connects as before,
and the login is an ordinary web page reached through the tunnel. The generated peer configuration gets one
comment line, ignored by the apps:

```
# Login = http://10.103.1.1:8181/
```

The trade-off is that the app can't ask for credentials:

- the user must open the page after connecting: the apps can't run anything when the tunnel comes up, and the
  operating systems show their captive portal prompt only for Wi-Fi networks. The page has an icon and a web app
  manifest for the home screen, its form is marked for password managers, and the redirect described in
  [Rules](#rules) leads any plain `http://` address to it
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
The secret can disappear later, for example with the removal of the user's OpenVPN account, which deletes
`openvpn_2fa`: the login then refuses the peer (`no_otp`) instead of checking codes against an empty secret, which
`pyotp` accepts and anyone can compute. Saving the peer again creates a new secret, to send as a new QR code.

### Login service

`/etc/config/ns-wgauth`:

```
config main 'config'
	option port '8181'
	option redirect '1'
	option idle_timeout '300'
	option lock_endpoint '1'
	option detect_copies '1'
	option block_copies '0'
	option max_failures '5'
	option lockout_time '900'
```

- `redirect`: before the login, lead plain `http://` addresses to the login page, see [Rules](#rules). The
  optional `redirect_port` (8180) and `dns_port` (8153) are the local ports used for it
- `lock_endpoint`: `1` (strict), `roaming` or `0`, see [Copied configurations](#copied-configurations)
- `detect_copies`: watch the endpoints for a configuration used by two devices at once
- `block_copies`: block such a peer until an administrator acts, instead of only ending its session
- `max_failures`, `lockout_time`: failed logins from one public IP before it's locked out, and for how long

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
  `/www-wgauth` and proxies `/api/` to the daemon, adding request size limits and rate limiting (`limit_req`).
  With the redirect, a second server block on `redirect_port` sends the web requests made before the login to it
- the `ns-wgauth` daemon (`ns-wgauth serve`, Python, on `/var/run/ns-wgauth.sock`): it checks credentials, adds
  and removes set elements, answers the DNS queries redirected before the login, every 5 seconds watches the
  endpoints for copied configurations and every 15 seconds ends the sessions that are no longer valid
- `ns-wgauth sync`: it applies the configuration: it takes the snapshot the daemon works on, builds the table and
  the nginx server, and ends the sessions that are no longer valid
- `ns-wgauth check`: it tests on the firewall what can't be tested elsewhere, see [Failing closed](#failing-closed)
- `nethsec.wgauth` in python3-nethsec: the logic shared by the daemon and the `ns.wireguard` API

### Applied configuration

UCI keeps the changes saved but not applied yet in `/tmp/.uci`, and every reader sees them, the daemon too.
Without care, a server switched to `key` in the UI would lose its gate within 15 seconds, before the administrator
applies the change or even if they discard it; a new password would log the user out before it's applied.

So the daemon never reads UCI. `ns-wgauth sync`, run by the init script at boot and on every configuration reload,
writes a snapshot of what the login needs to `/var/run/ns-wgauth/state.json` (readable by root only, it holds the
password hashes and the OTP secrets of the linked users): the gated servers, their enabled peers by reserved IP with
public key, user, password hash, OTP secret and credentials fingerprint, and the `ns-wgauth` settings. The login
checks, the periodic checks and the gate all use this snapshot, so a change takes effect when it's applied, through
the procd reload triggers, and not before.

### Why a separate nftables table

fw4 rebuilds its `inet fw4` table on every reload, and commits from the UI reload it often. A set inside fw4,
for example through `/usr/share/nftables.d/table-pre` as ns-dpi does, would be emptied each time and every user
would be logged out. `fw4 start`, `reload`, `restart` and `stop` touch only `inet fw4`; banIP (threat shield)
relies on this with its own `table inet banIP`. Only `fw4 flush` deletes every table, see
[Failing closed](#failing-closed).

### Rules

`ns-wgauth sync` generates the table from the gated servers, enabled or not. With one gated server `wg1`, the
login port 8181 and the redirect on:

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

	chain prerouting {
		type nat hook prerouting priority dstnat - 1; policy accept;
		iifname "wg1" ip saddr != @auth_wg1 udp dport 53 limit rate 100/second redirect to :8153
		iifname "wg1" ip saddr != @auth_wg1 tcp dport 80 redirect to :8180
	}

	chain input {
		type filter hook input priority filter - 1; policy accept;
		iifname != @gated iifname != "lo" tcp dport { 8181, 8180 } drop
		iifname != @gated iifname != "lo" udp dport 8153 drop
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
		tcp dport { 8181, 8180 } accept
		udp dport 8153 accept
		icmp type echo-request accept
		meta l4proto tcp reject with tcp reset
		reject with icmpx type admin-prohibited
	}
}
```

Without the redirect, the `prerouting` chain and the rules on ports 8180 and 8153 are left out.

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
- Before the login there is no real DNS, not even to the firewall: its resolver forwards queries to the internet, so
  a copied configuration could tunnel data through it.
- The redirect: before the login, the DNS queries of a peer go to the daemon (`dns_port`), which answers every name
  with the address of the server (`dns_answer` in `nethsec.wgauth`, TTL 1 second, no record for AAAA and the other
  types) and forwards nothing, so DNS still can't carry data out. The queries are limited to 100 per second per
  server; the others are rejected. Web requests on port 80 go to an nginx server on `redirect_port`, which answers
  `302 http://$server_addr:8181/`: after the redirect `$server_addr` is the address of the WireGuard server the request
  came through. So any plain `http://` address, `http://neverssl.com` for example, opens the login page. `https://`
  addresses still fail, as on a captive portal, and the redirect works only for peers whose DNS queries go through
  the tunnel: all traffic routed, or the DNS of the server set to an address reached through it. At login the
  daemon deletes the conntrack entries of the peer for UDP port 53 and TCP port 80, so its queries and requests reach
  their real destination at once. Browsers that cache names regardless of the TTL, Firefox for example, may need a
  minute for the names opened just before the login.
- With no gated server the table is removed.

### Sessions

- Login: the daemon adds the peer's address to the server's set with the `ns_auth_timeout` timeout.
  A new login replaces the element and restarts the timer.
- What the firewall knows about each session is in `/var/run/ns-wgauth/sessions.json`: peer, public key, user,
  login time, public IP of the client, latest handshake seen and a fingerprint of the credentials (authentication
  mode, database, user name, password hash and, with OTP, the secret). A file lock serializes the daemon and the
  `sync` command.
- Expiry: nftables removes the element when the timeout ends; the next check forgets its metadata.
- Every 15 seconds, and on every `sync`, the sessions are checked against the
  [applied configuration](#applied-configuration). A session ends when:
  - its metadata is missing
  - the server is disabled or doesn't require the login anymore
  - the peer is disabled, removed, linked to another user, has another reserved IP or new keys
  - the user is removed, or its fingerprint changed (for example a new password)
  - the peer is blocked, see [Copied configurations](#copied-configurations)
  - the peer's latest handshake is older than `idle_timeout` (`wg show all latest-handshakes`). The generated
    configurations set `PersistentKeepalive = 25`, so a connected client renews its handshake about every
    2 minutes even when idle. The check remembers the latest handshake it has seen: a commit that touches a
    server restarts its interface (`restart-wireguard.py`) and resets the handshakes, and that must not end the
    sessions of its peers
  - with `lock_endpoint` set to `1` (the default), the peer sends from another public IP than at login
    (`wg show all endpoints`, the port is ignored). With `roaming` the session follows the peer to its new IP.
    See [Copied configurations](#copied-configurations)
- Logout: from the login page, or by the administrator with `ns.wireguard logout-peer` or `ns-wgauth logout`.
- Sessions live only in kernel memory and in `/var/run`: a reboot or an HA failover logs everyone out.

### Login API

nginx serves it at `http://<server address>:<port>/api/` and proxies it to the daemon, adding `X-Real-IP` (the
client address) and `X-Forwarded-Host` (the requested host).

- `GET /api/status`: `{"authenticated": false, "otp_required": true, "server": "Road warriors", "blocked": false,
  "no_user": false, "no_otp": false}`; with a session also `"user"` and `"expires"`. `blocked`, `no_user` and
  `no_otp` (OTP required but the user has no secret) let the page explain why the user can't log in
- `POST /api/login` with `{"username": "alice", "password": "...", "otp": "123456"}`:
  `{"result": "success", "user": "alice", "expires": "2026-10-24T18:00:00+00:00"}`
- `POST /api/logout` with `{}`: `{"result": "success"}`

Every request must come from the reserved IP of an enabled peer on an enabled gated server, and must be addressed to
the server's address: a page of another site whose name resolves to that address (DNS rebinding) gets
`403 {"error": "forbidden"}`. `login` and `logout` accept only `Content-Type: application/json`: a form on another
site can't send it without a CORS preflight, which the API never answers.

The login checks:

1. the peer isn't blocked (`403 {"error": "blocked"}`), has a user (`403 {"error": "no_user"}`) and, with
   `key_password_otp`, the user has an OTP secret (`403 {"error": "no_otp"}`)
2. the public IP of the client isn't locked out: after `max_failures` failures from that IP it gets
   `429 {"error": "too_many_attempts"}` for `lockout_time` seconds. The failures are counted per public IP
   (`wg show all endpoints`), not per peer: someone trying passwords with a copied configuration from another network
   doesn't lock out the real user. So that many IPs don't multiply the attempts, a peer failing `4 × max_failures`
   times in `lockout_time` from any IP is locked out everywhere but at the IP of its latest successful login.
   A lockout is recorded as an alert of the peer. nginx also limits the login requests of a VPN address
   (30 per minute): every copy of a configuration shares that address, so the limit only stops floods
3. the username matches the peer's `ns_user`, case insensitive like `users.get_user_by_name()`
4. the user exists in `ns_user_db` and `users.check_password()` accepts the password
5. with `key_password_otp`, the TOTP code is valid (`pyotp`, accepting the previous and next 30 seconds) and wasn't
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
- if nftables refuses the login rules, and the table in place doesn't already gate every server, `sync` loads
  fallback rules instead: `iifname "wg1" drop` and `oifname "wg1" drop` in the input and forward chains, with a
  numeric priority and nothing else, so they don't depend on the syntax of the login rules. Nobody can log in, but
  nobody gets through with the key alone. If even those are refused, the daemon takes the server interfaces down
  (`ubus call network.interface down`). Both states are recorded in `/var/run/ns-wgauth/blocked.json`, logged once,
  and undone as soon as the login rules load, for example after a fix
- `ns.wireguard list-servers` reports `auth_enforced: false` when a server requires the login but its set is
  missing, and `auth_blocked: true` when the fallback rules block it, so the UI can warn the administrator
- `ns-wgauth check` asks nftables to validate both rule sets without applying them (`nft -c`), runs `nginx -t`,
  checks the table, the nginx server and the daemon, and warns about peers without a user and about peers sharing a
  public IP (a router hiding the client IPs, see [Behind NAT](#behind-nat))

The init script registers procd reload triggers on the `network`, `users` and `ns-wgauth` configurations:
any commit that adds a server, changes a peer or a password runs `sync` again. Starting the daemon is also decided
there: it runs only while a server requires the login.

## Copied configurations

The goal is that a leaked or copied peer configuration alone doesn't give access to the VPN.

- **The configuration alone**: the copy completes the WireGuard handshake, because the key is valid, but reaches
  only the login page and ping. Without the username, the password and, with `key_password_otp`, the OTP code of the
  linked user, it gets nothing else. Wrong attempts lock out the public IP they come from (`max_failures`,
  `lockout_time`), not the peer, so the real user can still log in from another network; every failure is logged and
  a lockout becomes an alert of the peer. The page doesn't tell the username.
- **The configuration used while the user is logged in**: WireGuard can't tell apart two devices with the same key,
  and the session belongs to the key. With `lock_endpoint` set to `1`, the session is bound to the public IP the
  client had at login: when the copy sends from another network the session ends within 15 seconds. The legitimate
  user must log in again; while both devices are active, neither keeps a session.
- **Two devices at once**: WireGuard sends to the public IP of the latest packet received, so while two devices with
  the same key are active the endpoint of the peer keeps switching between their IPs. Every 5 seconds the daemon
  reads the endpoints of the gated peers (`CopyDetector` in `nethsec.wgauth`): three changes within 5 minutes that go
  back to an IP already seen mean two devices, whereas a device that changes network moves once, or always to new
  IPs. Then, whether the user is logged in or not, the session of the peer ends, a `possible copy of the
  configuration` warning is logged and an alert is recorded, at most once an hour while both devices stay active.
  With `block_copies` the peer is also blocked: the login page refuses it until an administrator clears its alerts or
  generates new keys.
- **Alerts**: they are kept in `/etc/ns-wgauth/alerts.json`, across reboots and upgrades (`/lib/upgrade/keep.d`),
  at most 20 per peer and for 30 days. They belong to the keys of the peer: once new keys are applied, the old alerts
  and the block are dropped. `ns.wireguard list-servers` returns them per peer, and the UI shows them.
- **The response to a leak**: generate new keys for the peer (`ns.wireguard regenerate-peer-keys`), apply, and give
  the new configuration to the user. Every copy of the old one stops working, even with the password.
- **Limits**: two devices behind the same public IP (the same office or home network) can't be told apart. With
  `lock_endpoint` set to `1`, a user who changes network, for example from Wi-Fi to 4G, logs in again; with
  `roaming` the session follows them, and a copy used while the real device is off or asleep, so without switching,
  keeps the session until it expires.
- **Configuration, password and OTP secret leaked together** defeat the login: deliver them through different
  channels, and enroll the OTP in person or over a screen share.

Defguard closes the second case differently: its desktop client receives a new preshared key after every MFA
login, so a copy without that key can't even complete the handshake. That needs a custom client, which this design
avoids.

The firewall keeps the private keys of the peers, in its configuration and in its backups, as before this feature.

### Behind NAT

The firewall can sit behind a router that forwards the WireGuard UDP port to it, with a single network card:

- only the WireGuard port is forwarded: the login page is reached through the tunnel
- the endpoints seen by the firewall must be the public IPs of the clients (check with `wg show wg1 endpoints`, or
  `ns-wgauth check`, which warns when peers share an IP). A port forward keeps them; if the router also masquerades
  the forwarded traffic, every client shows the router address, `lock_endpoint` must be disabled because it can't
  tell clients apart, and the copy detection can't work either
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
- `list-servers`: servers also return `auth_mode`, `user_db`, `auth_timeout`, `login_url`, `auth_enforced` and
  `auth_blocked`; peers also return `user`, `authenticated`, `auth_expires`, `blocked` and `alerts` (newest first,
  `{"time": "...", "type": "copy" | "lockout", "addresses": ["198.51.100.20"]}`).
- new `logout-peer` (`{"id": "wg1_ns_1234abcd_peer"}`): ends the peer's session. It changes no UCI option,
  so there is nothing to commit.
- new `download-peer-2fa` (`{"id": "wg1_ns_1234abcd_peer"}`): returns the OTP QR code of the linked user as SVG,
  like `ns.ovpnrw download-user-2fa`.
- new `regenerate-peer-keys` (`{"id": "wg1_ns_1234abcd_peer"}`): new private and public keys for a server peer, and
  a new pre-shared key if it has one. The change is saved, to be applied with `ns.commit`.
- new `clear-peer-alerts` (`{"id": "wg1_ns_1234abcd_peer"}`): forgets the alerts of the peer and unblocks it. Like
  `logout-peer`, it changes no UCI option.
- the peer configuration gets the `# Login = ...` comment on gated servers.

The ACL `ns.wireguard.json` already allows every method of `ns.wireguard`.

### ns.users

No changes. Deleting a user, or changing its password, ends its sessions at the next `sync`, run by the procd
trigger on the `users` configuration. The peers linked to a deleted user stay, but can't log in until they are
linked to another user.

## Packaging

The `ns-wgauth` package (`PKGARCH:=all`), enabled by `config/ns-wgauth.conf`:

- `/usr/sbin/ns-wgauth`: the daemon and the `sync`, `check`, `needed`, `status`, `logout`, `alerts` and `clear`
  commands
- `/etc/init.d/ns-wgauth`: `START=15`, procd reload triggers, the daemon only while a server is gated
- `/etc/config/ns-wgauth`
- `/lib/upgrade/keep.d/ns-wgauth`: keeps `/etc/ns-wgauth/` and so the alerts across upgrades
- `/www-wgauth/`: the login page, plain HTML, CSS and JavaScript without inline code, its icon (SVG and PNG) and a
  web app manifest for the home screen
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
- The alerts, and so the blocked peers, survive an upgrade; the sessions don't.
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
- peer list: user ("No user" warning when missing), logged-in state, session expiry, blocked state and alerts,
  log-out, OTP QR code download, clear warnings and generate new keys actions
- server form: warning that the peers without a user can't log in once the login is required
- server card: login page address, warning when `auth_enforced` is `false`, error when `auth_blocked` is `true`

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
- connection history, like the `connections.db` of OpenVPN Road Warrior
- a companion app that opens the login page when the tunnel comes up

## Open questions

- Keep `openvpn_2fa` as the OTP secret, or move to a generic option name with a migration?
- Defaults: session length (8 hours), idle timeout (5 minutes), login port (8181).
