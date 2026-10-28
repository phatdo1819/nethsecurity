# Testing the WireGuard login

This branch, `ci-wgauth`, builds a NethSecurity image with the WireGuard login: the peers of a WireGuard server
must log in on a web page with a username, a password and an OTP code before they can use the VPN.
A copied peer configuration alone gives no access, and a copy used at the same time as the real device is detected.
With device binding (step 9), a server also accepts the login only from the device enrolled for the peer.
How it works: [design document](docs/design/wireguard_user_auth.md),
[device binding](docs/design/wireguard_device_binding.md) and [ns-wgauth](packages/ns-wgauth/README.md).

The image also contains everything of `ci-fork`: the Road Warrior multi-server changes and OpenVPN with DCO.
It's built from the development branch of NethSecurity, newer than 8.8.0: install it only on a test firewall.

## 1. Build the image

On an x86_64 Linux machine, Ubuntu 24.04 for example, set up as in [Build on Ubuntu](FORK-TESTING.md#build-on-ubuntu)
(podman, 4 cores, 8 GB of RAM, 100 GB of disk). Then:

```sh
git clone -b ci-wgauth https://github.com/phatdo1819/nethsecurity.git nethsecurity-wgauth
cd nethsecurity-wgauth
./build-nethsec.sh
```

The first build takes a few hours; the next ones, after `git pull`, rebuild only what changed. The web UI is
downloaded from the `ci-wgauth` branch of [nethsecurity-ui](https://github.com/phatdo1819/nethsecurity-ui) at the
commit written in `packages/ns-ui/Makefile`. The image is
`bin/targets/x86/64/nethsecurity-8.8.0-dev.<...>-x86-64-generic-squashfs-combined-efi.img.gz`.

If you already have a clone of `ci-fork`, you can use it: `git fetch origin && git checkout ci-wgauth`.

Every push to `ci-wgauth` can also build the image on GitHub (Actions > build-main.yml, artifact **image**), in about
4 hours; commits marked `[skip ci]` don't start it.

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
scp bin/targets/x86/64/nethsecurity-*-combined-efi.img.gz $FW:/tmp/
ssh $FW "sysupgrade -v /tmp/nethsecurity-*-combined-efi.img.gz"
```

The firewall reboots, keeping its configuration. After 2 or 3 minutes, log in again and check:

```sh
grep VERSION= /etc/os-release              # 8.8.0-dev...
ns-wgauth check
```

`ns-wgauth check` asks nftables and nginx whether they accept the login rules, without applying anything. Before any
server requires the login it prints:

```
OK      nftables accepts the login rules
OK      nftables accepts the fallback rules
OK      nginx accepts its configuration
OK      no WireGuard server requires the login
```

An `ERROR` on the first line is the most likely problem of a first run on real hardware: send me the line.
Nothing is lost if it happens: the firewall then blocks the servers that require the login instead of letting
their peers in with the key alone (see step 7).

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
   - **Advanced settings > DNS servers**: an address the peers reach through the tunnel, for example the LAN address
     of the firewall. The redirect of step 6 needs it, unless the peers route all their traffic through the VPN.
     Configurations downloaded before this change have no DNS line: download them again.
   Editing a server that already has peers, the form lists the peers without a user: they can't log in until you
   choose one for each of them.
3. Save, then apply the changes with the button at the top of the page.
4. **Add peer**: give it a name and choose **User** `alice`. Save and apply.
5. In the menu of the peer: **Download configuration**, and **Download OTP QR code**. Scan the QR code with an
   authenticator app (Microsoft Authenticator, Google Authenticator, Aegis, 2FAS...).

The server card now shows **Login** and **Login page** (for example `http://10.103.1.1:8181/`), and no
"Login not enforced" or "VPN blocked" message. On the firewall:

```sh
ns-wgauth check                        # all OK, warnings for peers without a user
nft list table inet ns_wgauth          # the gate: sets and chains
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
   The browser offers to save the password: accept, the next time only the OTP code is needed.
5. The LAN works now. In the web UI the peer shows **Logged in until ...**.
6. **Log out** on the page: the LAN stops answering.
7. **The redirect**: still logged out, open `http://neverssl.com` (type the whole address, with `http://`): the login
   page opens instead. `https://` sites fail, as on a hotel Wi-Fi. After the login, `http://neverssl.com` shows the
   real site.
8. **Home screen**, on a phone: Safari > Share > **Add to Home Screen**, or Chrome > menu > **Add to Home screen**.
   The icon is a white keyhole on blue and opens the login page.

On the firewall:

```sh
ns-wgauth status                       # open sessions, with the public IP of each client
grep ns-wgauth /var/log/messages       # logins, failures, logouts, warnings
wg show wg1 endpoints                  # use the name of your server: wg1, wg2...
```

`wg show wg1 endpoints` must show the **public IP of the client**, not the address of your router.
`ns-wgauth check` warns when two peers send from the same IP. If every client shows the router, the router rewrites
the source of the forwarded traffic: disable the IP lock (see [Settings](#settings)), otherwise every client looks
the same and the copy detection can't work.

## 7. Test the protection

For the copy tests, import the same `.conf` on a second device on another network, for example a phone on 4G
while the laptop is on Wi-Fi. The detection needs the two devices active at the same time for a minute or two.

| Test | Expected |
|---|---|
| The copy, the owner logged out | The tunnel comes up, only the login page answers |
| 5 wrong passwords from the copy | **Too many failed attempts** on the copy for 15 minutes. The owner, on the other network, can still log in. The peer shows a warning icon in the web UI: "locked out after too many failed logins from ..." |
| The copy and the owner active at the same time, the owner logged in | Within a minute the owner loses the session (IP lock). Within about 2 minutes the peer shows a warning, "used from ... at the same time", and the log `possible copy of the configuration of peer ...` |
| The same, with `block_copies` set to `1` (see [Settings](#settings)) | The peer shows **Blocked**; the login page says the configuration is blocked, on both devices |
| Peer menu > **Clear warnings** | The warnings go, a blocked peer can log in again |
| Peer menu > **Generate new keys**, apply | The old configuration no longer connects, on any device; download the new one, the warnings are gone |
| The owner changes network (Wi-Fi to 4G) | The session ends, log in again. With `lock_endpoint` set to `roaming` the session continues |
| Turn the tunnel off for 6 minutes | The session ends |
| Change the password of `alice` and apply | The session ends. Before you apply, nothing changes: the old password still works |
| Set the server to *WireGuard key*, save **without applying**, wait a minute | The LAN still needs the login. Apply: it doesn't anymore. Set it back to *Key, user password and OTP* and apply |
| A peer without a user | The peer shows **No user**; its login page says it isn't linked to a user |
| Disable the peer, or **Log out** in the peer menu | The session ends |
| The same OTP code used twice | The second login is refused |
| `fw4 reload`, or edit another peer of the same server and apply | The session stays |
| `nft delete table inet ns_wgauth` | Within 15 seconds `nft list table inet ns_wgauth` shows it again; users log in again |
| Reboot the firewall | `nft list table inet ns_wgauth` exists right after boot; users log in again; warnings and blocks are still there |

## 8. Test the fallback endpoints and the connections

**Fallback endpoints**: edit the server, add one under **Fallback endpoints** (e.g. the IP of a second line, or
`host:port`), save and apply. The downloaded configuration has `# Fallback = ...` after `Endpoint`; the official
WireGuard apps still connect with `Endpoint`.

[Authway](https://github.com/phatdo1819/authway), the WireGuard client for Windows with the login, uses them (install
it from the MSI package of its repo): when the server doesn't answer at an address for 20 seconds, it moves to the
next one, the tunnel and the login stay. Import the new configuration (it replaces the old one), connect:
**Details...** shows the fallbacks and *Address in use: ... (main)*.

- Quick test, without touching the lines: in a copy of the `.conf`, set `Endpoint` to an address that doesn't answer
  (e.g. `192.0.2.1:51820`) and put the real one in `# Fallback = ...`, import it under another name and connect. About
  20 seconds later the tunnel comes up on the fallback and the login window works.
- Real test: connect through line 1, then take line 1 away (unplug it, or turn off its port forward on the router).
  Within about 20 seconds of traffic (open a page) the client moves to line 2, *Address in use* says *(fallback 1)*,
  and the session stays: no new login, as long as the line is down for less than 5 minutes (`idle_timeout`).
  When line 1 comes back the client stays on line 2 until that one fails; the next **Connect** starts with line 1.

The service log, `C:\Program Files\Authway\log\service.log` (menu **Logs**), has
`no answer from <address> for 20 seconds, now <fallback>`, then `<fallback> answers`. The router must forward the
port on both lines, and send the answers back out the line they came in on.

**Connections**: the new **Connections** tab of the WireGuard page. Connect a peer and wait a minute: a row appears,
**Connected**, with the public IP of the client and the bytes. Disconnect: about 3 minutes later the row gets its end.
Check also the CSV download, and on the firewall:

```sh
grep wireguard-history /etc/crontabs/root   # every minute
/usr/libexec/wireguard-history; echo $?     # 0
api-cli ns.wireguard connection-history
```

The history is in `/var/wireguard/connections.db` (lost at reboot), or on the data storage if there is one.

## 9. Test device binding

A server with **Device binding** accepts the login only from the device enrolled for each peer: the VPN app signs
every login with a key that never leaves the computer, and the first login enrolls it. A copy of the configuration,
even with the password and the OTP code, then fails on another computer. With **Machine ID** the app also sends a
hash of the hardware ID of the computer. Only [Authway](https://github.com/phatdo1819/authway) can log in on such a
server: the browser and the official WireGuard apps can't sign.

### Install it on the firewall without rebuilding

An image built from `ci-wgauth` before device binding can get it by copying files: the firewall side is Python and
static files, `openssl` is already in the image. A new image built after these changes already has it: skip to
[Set it up](#set-it-up).

From the folder of the repository with the changes, in Git Bash on Windows or bash elsewhere (on the Windows PC of
the development, the changes are in `C:\Users\phatdo\nethsecurity-feat` until they are committed):

```sh
FW=root@192.168.1.1     # your firewall
NETHSEC=$(ssh $FW "python3 -c 'import nethsec, os; print(os.path.dirname(nethsec.__file__))'")

# 1. back up the current files, once
ssh $FW "mkdir -p /root/device-binding-backup && cp $NETHSEC/wgauth/__init__.py /root/device-binding-backup/wgauth.py && cp /usr/sbin/ns-wgauth /usr/libexec/rpcd/ns.wireguard /root/device-binding-backup/ && cp -a /www-wgauth /www-ns /root/device-binding-backup/"

# 2. the firewall files
scp packages/python3-nethsec/src/nethsec/wgauth/__init__.py $FW:$NETHSEC/wgauth/__init__.py
scp packages/ns-wgauth/files/ns-wgauth.py $FW:/usr/sbin/ns-wgauth
scp packages/ns-wgauth/files/www/* $FW:/www-wgauth/
scp packages/ns-api/files/ns.wireguard $FW:/usr/libexec/rpcd/ns.wireguard
# a clone on Windows has Windows line endings: they break the scripts
ssh $FW "sed -i 's/\r$//' /usr/sbin/ns-wgauth /usr/libexec/rpcd/ns.wireguard /www-wgauth/app.js"
```

The web UI comes from the `ci-wgauth` branch of nethsecurity-ui, with the device binding changes: build it with
`npm ci` and `npm run build-only` (the result is in `dist`; on the Windows PC of the development it's already built in
`C:\Users\phatdo\nethsecurity-ui\dist`). A build of another branch would lose the Road Warrior changes of the image.
Copy it, keeping the branding of the firewall:

```sh
UI=../nethsecurity-ui/dist      # the folder of the UI build
ssh $FW "rm -rf /tmp/ui && mkdir /tmp/ui"
scp -r $UI/* $FW:/tmp/ui/
ssh $FW "rm -f /tmp/ui/branding.js && cp -a /tmp/ui/. /www-ns/ && rm -rf /tmp/ui"

# 3. restart: rpcd learns the new API methods, ns-wgauth takes the new configuration
ssh $FW "which openssl && /etc/init.d/rpcd restart && /etc/init.d/ns-wgauth restart && ns-wgauth check"
```

Reload the web UI with Ctrl+F5. To undo, copy the files of `/root/device-binding-backup/` back to the same places
(`wgauth.py` to `$NETHSEC/wgauth/__init__.py`), then restart `rpcd` and `ns-wgauth`.

### The client

Authway signs the login from the version with device binding: build its package from its repository
([Build](https://github.com/phatdo1819/authway#build): `tools\fetch-wireguard.ps1`, then `tools\dist.ps1` on Windows;
`tools/fetch-wireguard-go.sh`, then `tools/dist-macos.sh` on a Mac) and install it over the old one: the VPNs stay.
An older Authway gets **device required** on a bound server.

### Set it up

1. Edit the server of step 5: in the login section turn on **Device binding**. Leave **Machine ID** off for the
   first tests. Save and apply.
2. The server card shows **Device binding: On** and the peer table a **Device** column: every peer shows
   *Waiting for the first login*, for 72 hours (`enroll_window`).
3. On the firewall, `ns-wgauth check` prints `OK  wg1 requires device binding`, and `ns-wgauth devices` the open
   enrollments.

### Tests

| Test | Expected |
|---|---|
| Open the login page in a browser | It says that only the VPN app on the enrolled device can log in; no form |
| Authway: connect and log in | The window says the first login enrolls this computer. After the login the peer shows the name of the computer in **Device**; its tooltip shows when, from which IP, and the key `software` |
| Disconnect, connect and log in again from the same computer | It works, without a new enrollment |
| Import the same `.conf` in Authway on another computer, log in with the right password and code | **This VPN configuration is enrolled on another device**. The peer shows a warning, "login attempt from another device", once an hour at most. The password isn't even checked: 5 tries lock out that IP |
| Peer menu > **Revoke device** | The session ends at once. Authway shows *no device enrolled*; the peer shows **No device**, and `ns-wgauth check` warns |
| Peer menu > **Allow a new device**, then log in from the second computer | The second computer is enrolled; the first one is refused |
| Remove the VPN from Authway, add it again, log in | Refused: removing a VPN deletes its key. Allow a new device first |
| Peer menu > **Generate new keys**, apply, import the new `.conf` | The peer waits for the first login again, for 72 hours |
| Turn **Machine ID** on, apply, log in | It works; the tooltip says the machine ID is recorded (the first login after turning it on records it) |
| Turn **Device binding** off, apply | The browser and the WireGuard apps can log in again. On again: the devices enrolled before work at once |

On the firewall:

```sh
ns-wgauth devices                       # enrolled devices, open enrollments
ns-wgauth alerts                        # the device_mismatch warnings
grep ns-wgauth /var/log/messages | grep -i device
ls -l /etc/ns-wgauth/devices.json       # root only: -rw-------
```

The log has `device enrolled: peer=... name=... from=...` for every enrollment: check it's the computer you expect.

In Authway, the service log (`C:\Program Files\Authway\log\service.log`, menu **Logs**) has `new device key` at the
first signed login. The key is kept by Windows (a key of the computer, `Authway device {GUID}`), and can't be
exported.

## Settings

`/etc/config/ns-wgauth`, changed with `uci`. The changes take effect when applied:

```sh
uci set ns-wgauth.config.lock_endpoint='roaming'  # the session follows a user who changes network
uci set ns-wgauth.config.block_copies='1'         # block a peer whose configuration is used twice at once
uci set ns-wgauth.config.idle_timeout='14400'     # log in once per workday: 4 hours without handshake
uci commit ns-wgauth
reload_config
```

Options: `port` (8181), `redirect` (1), `idle_timeout` (300 seconds, 0 disables it), `lock_endpoint` (`1`,
`roaming` or `0`), `detect_copies` (1), `block_copies` (0), `max_failures` (5 per public IP), `lockout_time`
(900 seconds), `enroll_window` (259200 seconds, 72 hours, for device binding). If the redirect causes any trouble,
`uci set ns-wgauth.config.redirect='0'` turns it off.

## Update without rebuilding

The login is Python and static files: after a fix to them, copy them instead of building a new image. From the
repository folder, bash:

```sh
FW=root@192.168.1.1
NETHSEC=$(ssh $FW "python3 -c 'import nethsec, os; print(os.path.dirname(nethsec.__file__))'")
scp packages/python3-nethsec/src/nethsec/wgauth/__init__.py $FW:$NETHSEC/wgauth/__init__.py
scp packages/ns-wgauth/files/ns-wgauth.py $FW:/usr/sbin/ns-wgauth
scp packages/ns-wgauth/files/www/* $FW:/www-wgauth/
scp packages/ns-wgauth/files/config $FW:/tmp/ns-wgauth.default   # new options: compare with /etc/config/ns-wgauth
scp packages/ns-api/files/ns.wireguard $FW:/usr/libexec/rpcd/ns.wireguard
# only from a clone on Windows: remove the Windows line endings
ssh $FW "sed -i 's/\r$//' /usr/sbin/ns-wgauth /usr/libexec/rpcd/ns.wireguard /www-wgauth/*.js"
# rpcd learns the API methods added by the change
ssh $FW "/etc/init.d/rpcd restart && /etc/init.d/ns-wgauth restart && ns-wgauth check"
```

Changes to the web UI need the image, or a build of the `ci-wgauth` branch of nethsecurity-ui copied as in
[step 9](#install-it-on-the-firewall-without-rebuilding).

## If something doesn't work

Collect this and send it:

```sh
ns-wgauth check
grep ns-wgauth /var/log/messages | tail -50
nft list table inet ns_wgauth
ns-wgauth status
ns-wgauth alerts
ns-wgauth devices
wg show
cat /etc/nginx/conf.d/ns-wgauth.conf
uci show network | grep -E "ns_auth|ns_user|ns_type|ns_device|ns_machine"
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
- Sessions are lost on reboot or HA failover: users log in again. Warnings and blocks stay.
- Two devices behind the same public IP can't be told apart: neither the IP lock nor the copy detection see them.
- The standard WireGuard apps can't open the login page by themselves: bookmark, home-screen icon or redirect.
- Firefox may keep for a minute the names opened just before the login: reload the page if a site doesn't open
  right after logging in.
- Device binding works only with Authway (Windows and macOS): no phones, no Linux, no browser on a bound server.
  Its key is a software key: an administrator of the enrolled computer could copy it. It controls the login only:
  a copy behind the same public IP as the logged-in owner still shares the session.
