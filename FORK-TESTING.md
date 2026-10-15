# Testing the OpenVPN Road Warrior multi-instance changes without rebuilding

Instead of building a new image, this guide copies the changed files onto a running
NethSecurity and keeps a backup, so you can test or update them in a few minutes and
roll back with one command.

It works on:

- an official **NethSecurity 8.8.0** install
- an image built from the `ci-fork` branch, to try later fixes without rebuilding it

Only the Road Warrior files are replaced, everything else stays as shipped.

## What you need

- `root` SSH access to the firewall
- on your computer: `git`, `ssh`/`scp` and, to update the web UI, Node.js 22 or newer.
  Windows (also on ARM), macOS and Linux all work: no OpenWrt build is needed

## 1. Get the code

```sh
git clone -b ci-fork https://github.com/phatdo1819/nethsecurity.git
git clone https://github.com/phatdo1819/nethsecurity-ui.git
```

If you already have the clones, update them with `git switch ci-fork` and `git pull`
inside `nethsecurity`.

## 2. Build the web UI

Pick the UI branch matching the firewall:

| Firewall | UI branch |
|---|---|
| Official 8.8.0 | `test/8.8.0`: the changes on top of the UI shipped with 8.8.0 |
| Image built from `ci-fork` | `feat/ovpnrw-multi-instance`, or skip this step: the image already contains it |

```sh
cd nethsecurity-ui
git switch test/8.8.0
git pull
npm ci
npm run build-only
cd ..
```

The result is in `nethsecurity-ui/dist`.

## 3. Copy the files to the firewall

Run these from the folder containing both clones. Set `FW` to your firewall first.

PowerShell:

```powershell
$FW = "root@192.168.1.1"
```

bash:

```sh
FW=root@192.168.1.1
```

The rest is the same in both shells:

```sh
ssh $FW "rm -rf /tmp/ns-test && mkdir -p /tmp/ns-test"
scp nethsecurity/tools/fork-test/install-on-device.sh nethsecurity/packages/python3-nethsec/src/nethsec/ovpn/__init__.py nethsecurity/packages/ns-api/files/ns.ovpnrw nethsecurity/packages/ns-api/files/ns.users nethsecurity/packages/ns-api/files/ns.dashboard nethsecurity/packages/ns-openvpn/files/openvpn-local-auth nethsecurity/packages/ns-openvpn/files/openvpn-remote-auth nethsecurity/packages/ns-openvpn/files/openvpn-otp-auth nethsecurity/packages/ns-openvpn/files/01-check-status nethsecurity/packages/ns-openvpn/files/10-static-lease nethsecurity/packages/ns-openvpn/files/80-save-connection nethsecurity/packages/ns-openvpn/files/99_ns-openvpn-user-instances "${FW}:/tmp/ns-test/"
scp -r nethsecurity-ui/dist "${FW}:/tmp/ns-test/ui"
```

Skip the last command if you don't want to update the web UI.

## 4. Install

```sh
ssh $FW "sed 's/\r$//' /tmp/ns-test/install-on-device.sh | sh"
```

The script:

1. saves the original files in `/root/ns-test-backup`, the first time only
2. installs the new files
3. converts the existing Road Warrior users to per-instance membership, as the first boot of a new
   image does; `/etc/config/users` is saved first
4. installs the web UI, keeping the device branding
5. restarts `rpcd`

Reload the web UI with Ctrl+F5.

To install a newer version of the files, repeat steps 1–4: the backup of the originals is kept.

## 5. Test

1. **Upgrade path**: existing Road Warrior users can still connect, with their old `.ovpn` file.
2. **One account, two servers**: add a second server with a different port and network. Add the same
   user to both and connect to each one with the same password.
3. **Disable on one server**: disabling the user on server A drops only the connection to A.
4. **Delete the user** in Users & Objects: both connections drop. Create a user with the same name and
   add it to a server: it works, while the old `.ovpn` files are refused.
5. **Connection history**: the "all servers" view shows a Server column, and the CSV export contains
   the server name.
6. **Users filter**: the filter box on the Users & Objects page finds users by name or description.
7. **Traffic between servers** (routed servers only, off by default):
   1. connect a client to server A and one to server B; ping each other's VPN address: it fails
   2. edit server A, open the advanced settings and turn on "Allow traffic with other Road Warrior servers";
      save and apply the changes. The ping still fails: the option must be on for both servers
   3. turn it on for server B too and apply: both servers restart, the clients reconnect and get the routes.
      The ping now works in both directions
   4. turn it off on one of the two servers: the ping fails again
   5. the firewall rules page shows a system rule `Allow-OpenVPNRW<N>-inter-server` for each enabled server
      while the traffic is allowed, and none when it is not

   Windows blocks incoming ping by default: allow it in the Windows firewall of the client you ping, or test
   with another service, such as a shared folder.
8. **Many servers**:
   1. with up to 5 servers each one has a tab; give one a long name: the tab bar scrolls instead of the page
   2. add servers until there are 6: the tab bar shows only "Servers" and "Connection history", and a
      "Server" list, searchable by name, selects the server. Disabled servers are marked in the list
   3. open the connection history and go back to "Servers": the last server is shown again
   4. with more than 10 servers having connections, the "all servers" history and the CSV export include
      every server, and filtering on any single server shows its connections
   5. delete servers until there are 5: each server gets its tab back

Useful commands on the firewall:

```sh
logread -e openvpn
api-cli ns.ovpnrw list-instances
uci show users | grep openvpn_
uci show openvpn | grep -E 'ns_inter_server|push'
uci show firewall | grep inter_server
ip route
```

On a client, `route print` (Windows) or `ip route` (Linux) shows the routes received from the server.

## Undo

Before undoing, turn off "Allow traffic with other Road Warrior servers" on all the servers and apply the
changes: the original files don't know the option, so they would leave its routes and firewall rules in place.

```sh
ssh $FW "sh /root/ns-test-backup/install-on-device.sh --restore"
```

This puts back the original files and the original web UI. The users configuration is not restored, because
it may contain users you added during the test; the version from before the first install is
`/root/ns-test-backup/users.config`. The older code keeps working with the converted users.

## Known limitations

- On an official 8.8.0, the dashboard "Threat Shield" blocked-IP counter shows 0: the new `ns.dashboard`
  reads it from a metric that 8.8.0 does not collect yet. Everything else on the dashboard works.
- Installing a system or package update replaces some of these files with the official version.
  Repeat steps 3 and 4 afterwards, or restore first.
- A reboot does not undo the files, they stay installed.
