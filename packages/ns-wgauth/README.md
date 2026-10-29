# ns-wgauth

Login with user credentials for WireGuard servers.

A WireGuard key opens the tunnel, but the peers of a server that requires the login can reach only a login page on
the firewall until the user enters the username and password of a local users database, and optionally an OTP code.
The standard WireGuard clients work unchanged: the user opens the login page in a browser after connecting.

See the [design document](../../design/wireguard_user_auth) for the reasons behind the choices.

## Configuration

The login is enabled per server, in the network interface of a WireGuard server (`ns_type 'server'`):

- `ns_auth_mode`: `key` (default when the option is missing: no login), `key_password`, `key_password_otp`
- `ns_user_db`: the local users database
- `ns_auth_timeout`: session length in seconds, default `28800` (8 hours), from 300 to 604800

Each peer of such a server is linked to a user with the `ns_user` option, one peer per user and server:
`ns.wireguard` refuses a second one, and `ns-wgauth check` points out the peers that shared a user before the rule.
With `key_password_otp` the OTP secret is
the `openvpn_2fa` option of the user, the one used by OpenVPN Road Warrior. Removing the user's OpenVPN account
deletes it: the user can't log in until the peer is saved again, which creates a new secret (`ns-wgauth check`
reports it).

A server that requires the login can also require device binding: its peers log in only from the device enrolled
for them, with a VPN client that signs the login, see the [device binding design](../../design/wireguard_device_binding).
The browser and the official WireGuard apps can't log in on such a server.

- `ns_device_binding`: `1` to require it. Only with a login: switching `ns_auth_mode` to `key` removes it
- `ns_machine_id`: `1` to also require the hardware ID of the enrolled machine

Use the `ns.wireguard` API to change these options, see `packages/ns-api/README.md`.

The login service is configured in `/etc/config/ns-wgauth`:

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

- `port`: TCP port of the login page, reachable only from the WireGuard interfaces that require the login
- `redirect`: `1` to lead any plain `http://` address to the login page before the login: the DNS queries of the
  peer get a fake answer, the address of the server, and its web requests on port 80 a redirect to the login page.
  Nothing is forwarded. It works when the DNS queries of the peers go through the tunnel. The local ports used are
  `redirect_port` (8180) and `dns_port` (8153), optional
- `idle_timeout`: seconds without a WireGuard handshake after which a session ends, `0` to disable the check
- `lock_endpoint`: what happens when a peer sends from another public IP than at login
  - `1`: the session ends, so a copied configuration can't share the session of the real user. A user who changes
    network, for example from Wi-Fi to 4G, logs in again
  - `roaming`: the session follows the peer. Two devices used at once are still caught by `detect_copies`, but a
    copy used while the real device is off keeps the session
  - `0`: the IP is ignored, for example when the router in front of the firewall masquerades the WireGuard traffic
    and every client shows the same IP
- `detect_copies`: `1` to watch the endpoints every 5 seconds: when the endpoint of a peer keeps switching between
  public IPs, two devices use its configuration. The session ends and an alert is recorded
- `block_copies`: `1` to also block such a peer until an administrator clears its alerts or generates new keys
- `max_failures`: failed logins from one public IP before it's locked out
- `lockout_time`: seconds a public IP stays locked out
- `enroll_window`: seconds a peer of a server with device binding can enroll its device, from its creation, its new
  keys, or the binding of its server, default `259200` (72 hours)

The changes take effect when they are applied (`uci commit ns-wgauth; reload_config`, or the Apply button of the
UI): the daemon works on the configuration taken by `ns-wgauth sync`, not on the changes saved but not applied yet.

The login page is `http://<server address>:<port>/`, for example `http://10.103.1.1:8181/`. The generated peer
configurations contain it as a `# Login = ...` comment. With `redirect`, any plain `http://` address opened before
the login leads there too, `http://neverssl.com` for example. The page has an icon for the home screen of a phone,
and its form is marked for password managers, so the browser can remember the username and password.

The page is plain HTTP: `https://` addresses don't work on the login port. The password still travels encrypted,
inside the WireGuard tunnel, and the port is reachable only from the tunnel. Browsers may mark the password field as
not secure.

## How it works

- `ns-wgauth sync` applies the configuration. It writes the snapshot the daemon works on
  (`/var/run/ns-wgauth/state.json`) and builds the `inet ns_wgauth` nftables table: a set of logged-in addresses
  per server (`auth_<server>`) and the chains that block everything else coming from or going to the server
  interface, except the login page and ping to the firewall. The chains run just before fw4, so fw4 rules still
  apply to the logged-in peers. The table is separate from fw4: firewall reloads don't end the sessions.
- If nftables refuses those rules, fallback rules block all the traffic of the servers that require the login, and
  if even those are refused, their interfaces are taken down: the VPN fails closed. The UI shows "VPN blocked".
- `ns-wgauth serve` answers the login API on `/var/run/ns-wgauth.sock`. nginx serves the static page from
  `/www-wgauth` and proxies `/api/` to the socket (`/etc/nginx/conf.d/ns-wgauth.conf`, generated by `sync`).
- A login adds the peer address to the server set with the session length as timeout. A session ends when it expires,
  when the user logs out, when the peer doesn't handshake for `idle_timeout` seconds, when it sends from another
  public IP (`lock_endpoint`), when its configuration seems used by two devices (`detect_copies`), and when a change
  to the peer (new keys too), the user (for example a new password) or the server is applied. Ending a session also
  deletes the conntrack entries of the peer, so its open connections stop.
- Suspected copies, lockouts and logins from another device are recorded as alerts of the peer in
  `/etc/ns-wgauth/alerts.json`, kept across reboots and upgrades. They belong to the keys of the peer: generating new
  keys drops them.
- With device binding, the enrolled devices and the open enrollments are in `/etc/ns-wgauth/devices.json`, kept the
  same way and tied to the keys of the peer too. The signatures are checked with `openssl`.
- The init script runs before the network, so the gate exists before the WireGuard interfaces come up. procd runs it
  again when the `network`, `users` or `ns-wgauth` configuration changes. The daemon runs only while a server
  requires the login, and checks the table and the sessions every 15 seconds: if the table is missing, it builds
  it again.

Logins (with the public IP of the client), failures, logouts and possible copies of a configuration are
logged to `/var/log/messages` with the `ns-wgauth` tag:

```
grep ns-wgauth /var/log/messages
```

## Commands

```
ns-wgauth check           # test the nftables rules and nginx, report the state of the gate
ns-wgauth status          # open sessions, as JSON
ns-wgauth logout <peer>   # end the session of a peer, e.g. wg1_ns_1234abcd_peer
ns-wgauth alerts          # suspected copies and lockouts, as JSON
ns-wgauth clear <peer>    # forget the alerts of a peer and unblock it
ns-wgauth devices         # enrolled devices and open enrollments, as JSON
ns-wgauth sync            # apply the configuration now
nft list table inet ns_wgauth
```

`ns-wgauth check` prints one line per check, `OK`, `WARNING` or `ERROR`, and exits with 1 if any check failed.
It asks nftables to validate the rules without applying them (`nft -c`), so it's safe to run at any time.

## Login API

The API is reachable only from the WireGuard peers, through nginx on the login port. The client is identified by
its address in the VPN, and the page must be opened with the address of the server (other host names are refused).
`login` and `logout` accept only JSON requests.

- `GET /api/status`: `{"authenticated": false, "otp_required": true, "server": "Road warriors", "blocked": false,
  "no_user": false, "no_otp": false}`, with a session also `"user": "alice"` and `"expires": "..."`
- `POST /api/login` with `{"username": "alice", "password": "...", "otp": "123456"}`:
  `{"result": "success", "user": "alice", "expires": "2026-10-24T18:00:00+00:00"}`
- `POST /api/logout` with `{}`: `{"result": "success"}`

Errors: `403 {"error": "forbidden"}` (not a peer of a server that requires the login),
`403 {"error": "blocked"}` (suspected copy, see `block_copies`), `403 {"error": "no_user"}` (no user linked to the
peer), `403 {"error": "no_otp"}` (OTP required, the user has no secret), `401 {"error": "invalid_credentials"}`, `429 {"error": "too_many_attempts", "retry_after": 840}`,
`400 {"error": "invalid_request"}`, `500 {"error": "internal_error"}`.

With device binding, the status also returns `"device": {"required": true, "enrolled": true, "enrollment_open": false,
"machine_id": false, "challenge": "..."}`, and the login needs a `device` object signed by the device, see the
[login protocol](../../design/wireguard_device_binding#login-protocol). More errors:
`403 {"error": "device_required"}`, `403 {"error": "device_not_enrolled"}`, `401 {"error": "device_mismatch"}` and
`401 {"error": "challenge_expired"}`.

## Limitations

- Local users databases only.
- Peers of these servers can't have remote networks: the login identifies a peer by its reserved IP.
- Sessions are kept in memory: after a reboot or an HA failover users log in again.
- Removing the package, or installing an image without it, removes the gate: the peers connect without a login.
  Switch the servers back to `key` or disable them first.
