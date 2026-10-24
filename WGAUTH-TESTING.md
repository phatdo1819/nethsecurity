# Testing the WireGuard login

This branch, `ci-wgauth`, builds a NethSecurity image with the WireGuard login: the peers of a WireGuard server
must log in on a web page with a username, a password and an OTP code before they can use the VPN.
A copied peer configuration alone gives no access. How it works: [design document](docs/design/wireguard_user_auth.md)
and [ns-wgauth](packages/ns-wgauth/README.md).

The image also contains everything of `ci-fork`: the Road Warrior multi-server changes and OpenVPN with DCO.
It's built from the development branch of NethSecurity, newer than 8.8.0: install it only on a test firewall.

## 1. Get the image

Every push to `ci-wgauth` builds the image on GitHub, in 3 to 4 hours.

1. Open <https://github.com/phatdo1819/nethsecurity/actions/workflows/build-main.yml> and pick the latest
   run of the `ci-wgauth` branch. It must be green.
2. At the bottom of the run page, under **Artifacts**, download **image**.
3. Unzip it: inside there is `nethsecurity-8.8.0-dev.<number>.<date>.<commit>-x86-64-generic-squashfs-combined-efi.img.gz`
   (the name can differ slightly). Don't unpack the `.img.gz` itself.

With the GitHub CLI:

```sh
gh run list --repo phatdo1819/nethsecurity --workflow build-main.yml --branch ci-wgauth --limit 3
gh run download <run id> --repo phatdo1819/nethsecurity --name image
```

To build it yourself instead, follow [Build on Ubuntu](FORK-TESTING.md#build-on-ubuntu) with
`git clone -b ci-wgauth https://github.com/phatdo1819/nethsecurity.git`.

## 2. Before installing

- Download a backup: **System > Backup and restore**. Keep it on your computer.
- The image replaces the files copied with [FORK-TESTING.md](FORK-TESTING.md): it already contains them.
  The configuration stays.
- Keep the official 8.8.0 image at hand, to go back (see [Go back](#go-back)).

## 3. Install

From the folder with the image. PowerShell:

```powershell
$FW = "root@192.168.1.1"
scp (Get-ChildItem .\nethsecurity-*-combined-efi.img.gz).FullName "${FW}:/tmp/"
ssh $FW "sysupgrade -v /tmp/nethsecurity-*-combined-efi.img.gz"
```

bash:

```sh
FW=root@192.168.1.1
scp nethsecurity-*-combined-efi.img.gz $FW:/tmp/
ssh $FW "sysupgrade -v /tmp/nethsecurity-*-combined-efi.img.gz"
```

The firewall reboots, keeping its configuration. After 2 or 3 minutes, log in again and check:

```sh
grep VERSION= /etc/os-release              # 8.8.0-dev...
ls /usr/sbin/ns-wgauth /etc/init.d/ns-wgauth
```

Clear the browser cache (or reload with Ctrl+F5) before opening the web UI, so you get the new one.

## 4. The router

Forward only the WireGuard UDP port (for example 51820) to the firewall, as you already do.
Don't forward the login port 8181: the login page is reached through the tunnel.

## 5. Set up a server with login

1. **Users and objects > Users database**: in the local database, add a user, for example `alice`, with a
   password.
2. **VPN > WireGuard tunnel > Server tunnel > Add server** (or edit an existing one):
   - **Public endpoint**: the public IP or name of your router
   - **Authentication**: *Key, user password and OTP*
   - **Users database**: *Local database*
   - **Session length**: 8 hours
3. Save, then apply the changes with the button at the top of the page.
4. **Add peer**: give it a name and choose **User** `alice`. Save and apply.
5. In the menu of the peer: **Download configuration**, and **Download OTP QR code**. Scan the QR code with an
   authenticator app (Microsoft Authenticator, Google Authenticator, Aegis, 2FAS...).

The server card now shows **Login** and **Login page** (for example `http://10.103.1.1:8181/`), and no
"Login not enforced" warning. On the firewall:

```sh
nft list table inet ns_wgauth          # the gate: sets and chains
pgrep -fa "ns-wgauth serve"            # the login service
cat /etc/nginx/conf.d/ns-wgauth.conf   # the login page on port 8181
```

The downloaded configuration contains a `# Login = http://...` line: the address users open after connecting.
Phone apps may drop this comment on import, so tell users the address too.

## 6. Test the login

On a client (Windows, macOS, Linux, Android or iOS WireGuard app), import the configuration and activate the tunnel.

1. **Before the login**: the app shows the tunnel as active, but nothing behind the firewall answers: open a LAN
   address, it fails at once. `ping <login page address>` works.
2. Open the login page, for example `http://10.103.1.1:8181/`. The browser may say "Not secure": the page is
   reachable only through the tunnel, which encrypts it.
3. A wrong password: **Wrong username, password or OTP code**.
4. The right username, password and OTP code: **You are logged in as alice**, with the end of the session.
5. The LAN works now. In the web UI the peer shows **Logged in until ...**.
6. **Log out** on the page: the LAN stops answering.

On the firewall:

```sh
ns-wgauth status                       # open sessions
grep ns-wgauth /var/log/messages       # logins, failures, logouts
wg show wg1 endpoints                  # use the name of your server: wg1, wg2...
```

`wg show wg1 endpoints` must show the **public IP of the client**, not the address of your router.
If it shows the router for every client, the router rewrites the source of the forwarded traffic: disable the
IP lock (see [Settings](#settings)), otherwise every client looks the same.

## 7. Test the protection

| Test | Expected |
|---|---|
| Import the same `.conf` on a second device, the owner logged out | The tunnel comes up, only the login page answers |
| 5 wrong passwords in a row | **Too many failed attempts**, for 15 minutes |
| The copy used while the owner is logged in, from another network (a phone on 4G, the owner on Wi-Fi) | Within 15 seconds both lose access; the log shows `possible copy of the configuration of peer ...` |
| The owner changes network (Wi-Fi to 4G) | The session ends, log in again: expected with the IP lock |
| Turn the tunnel off for 6 minutes | The session ends |
| Change the password of `alice` and apply | The session ends |
| Disable the peer, or **Log out** in the peer menu of the web UI | The session ends |
| The same OTP code used twice | The second login is refused |
| `fw4 reload` on the firewall, or edit another peer of the same server and apply | The session stays |
| Reboot the firewall | `nft list table inet ns_wgauth` exists right after boot; users log in again |

## Settings

`/etc/config/ns-wgauth`, changed with `uci`:

```sh
uci set ns-wgauth.config.lock_endpoint='0'   # disable the IP lock
uci set ns-wgauth.config.idle_timeout='900'  # 15 minutes without handshake before the session ends
uci commit ns-wgauth
reload_config
```

Options: `port` (8181), `idle_timeout` (300 seconds, 0 disables it), `lock_endpoint` (1), `max_failures` (5),
`lockout_time` (900 seconds).

## If something doesn't work

Collect this and send it:

```sh
grep ns-wgauth /var/log/messages | tail -50
nft list table inet ns_wgauth
ns-wgauth status
wg show
cat /etc/nginx/conf.d/ns-wgauth.conf
nginx -t -c /etc/nginx/uci.conf
uci show network | grep -E "ns_auth|ns_user|ns_type"
```

`wg show` doesn't print private keys, and the `uci` line keeps only the login options.

## Go back

**First switch every server to *WireGuard key* or disable it**: an image without this feature ignores the login
options, and the peers would connect with their key alone.

Then install the official 8.8.0 image the same way as in step 3. To get the Road Warrior changes back on it,
follow [FORK-TESTING.md](FORK-TESTING.md).

## Known limitations

- The new web UI strings are in English only.
- Local users databases only, not LDAP.
- Sessions are lost on reboot or HA failover: users log in again.
- Two devices behind the same public IP can't be told apart by the IP lock.
