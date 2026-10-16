# Testing the OpenVPN Road Warrior multi-instance changes without rebuilding

Instead of building a new image, this guide copies the changed files onto a running
NethSecurity and keeps a backup, so you can test or update them in a few minutes and
roll back with one command.

It works on:

- an official **NethSecurity 8.8.0** install
- an image built from the `ci-fork` branch, to try later fixes without rebuilding it

Only the Road Warrior files are replaced, everything else stays as shipped.

Optionally, it also installs OpenVPN with data channel offload (DCO), which moves the VPN traffic into
the kernel and uses all the CPU cores. Those files must be built on a x86_64 Linux machine first, see
[Build on Ubuntu](#build-on-ubuntu). The same section explains how to build a full image with all the changes.

## What you need

- `root` SSH access to the firewall
- on your computer: `git`, `ssh`/`scp` and, to update the web UI, Node.js 22 or newer.
  Windows (also on ARM), macOS and Linux all work: no OpenWrt build is needed

## 1. Get the code

```sh
git clone https://github.com/phatdo1819/nethsecurity.git
git clone https://github.com/phatdo1819/nethsecurity-ui.git
```

This checks out `feat/ovpnrw-multi-instance`, which holds the changes. The `ci-fork` branch,
used to build the image, contains the same files: you can copy them from either branch.

If you already have the clones, update **both** of them every time, before building or copying anything:

```sh
cd nethsecurity
git pull
git log -1 --oneline
cd ..
```

Compare the commit shown with the latest one on GitHub. Copying the files from an old clone
is the most common mistake: the new web UI then shows options that the firewall ignores,
for example a setting that turns itself off again after saving.

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
scp nethsecurity/tools/fork-test/install-on-device.sh nethsecurity/packages/python3-nethsec/src/nethsec/ovpn/__init__.py nethsecurity/packages/ns-api/files/ns.ovpnrw nethsecurity/packages/ns-api/files/ns.users nethsecurity/packages/ns-api/files/ns.dashboard nethsecurity/packages/ns-openvpn/files/openvpn-local-auth nethsecurity/packages/ns-openvpn/files/openvpn-remote-auth nethsecurity/packages/ns-openvpn/files/openvpn-otp-auth nethsecurity/packages/ns-openvpn/files/01-check-status nethsecurity/packages/ns-openvpn/files/10-static-lease nethsecurity/packages/ns-openvpn/files/80-save-connection nethsecurity/packages/ns-openvpn/files/99_ns-openvpn-user-instances nethsecurity/packages/ns-openvpn/files/99_ns-openvpn-client-to-client "${FW}:/tmp/ns-test/"
scp -r nethsecurity-ui/dist "${FW}:/tmp/ns-test/ui"
```

Skip the last command if you don't want to update the web UI.

To install DCO too, copy the archive built on Ubuntu with this exact name:

```sh
scp ns-dco-8.8.0.tar.gz "${FW}:/tmp/ns-test/ns-dco.tar.gz"
```

## 4. Install

```sh
ssh $FW "sed 's/\r$//' /tmp/ns-test/install-on-device.sh | sh"
```

The script:

1. saves the original files in `/root/ns-test-backup`, the first time only
2. installs the new files
3. converts the existing Road Warrior users to per-instance membership, as the first boot of a new
   image does; `/etc/config/users` is saved first
4. adds a firewall rule for each routed server with client-to-client enabled: with DCO that traffic
   goes through the firewall
5. installs the web UI, keeping the device branding
6. restarts `rpcd`
7. only with `ns-dco.tar.gz`: checks that the files match the kernel of the firewall, installs the new
   `openvpn` program and the `ovpn` kernel module, and restarts OpenVPN. The clients reconnect

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

   Ping the other client's VPN address, not the address of the other server (`.1`): that one belongs to
   the firewall, which answers it even without the option.

   Windows blocks incoming ping by default: allow it in the Windows firewall of the client you ping, or test
   with another service, such as a shared folder. Two clients that can ping each other in the office
   may still not answer each other through the VPN: Windows usually treats the VPN connection as a
   public network, where ping is blocked, and allows ping only from its own subnet.

   If the ping fails, find where the packets stop. On the firewall, run `tcpdump -ni tunrw<N> icmp` for
   the server of the client you ping, then ping from the other client:

   - no packets: the firewall does not forward them. Check that both servers have the option on, that the
     changes are applied and that the two `inter_server` firewall rules exist
   - only `echo request` packets: the firewall forwards them and the client you ping doesn't answer
     through the VPN. Check its firewall, and that it has the route to the network of the other server:
     without it the reply leaves through its normal connection
   - `echo request` and `echo reply` packets: the firewall delivers both, so check the client you ping from
8. **Many servers**:
   1. with up to 5 servers each one has a tab; give one a long name: the tab bar scrolls instead of the page
   2. add servers until there are 6: the tab bar shows only "Servers" and "Connection history", and a
      "Server" list, searchable by name, selects the server. Disabled servers are marked in the list
   3. open the connection history and go back to "Servers": the last server is shown again
   4. with more than 10 servers having connections, the "all servers" history and the CSV export include
      every server, and filtering on any single server shows its connections
   5. delete servers until there are 5: each server gets its tab back
9. **DCO** (only with `ns-dco.tar.gz`):
   1. `lsmod | grep ovpn` shows the module, and `ip -d link show tunrw1` shows `ovpn` instead of `tun`
      for every routed server. `grep -i openvpn /var/log/messages | grep -i dco` explains why a server doesn't use it:
      bridged servers, CBC ciphers and compression turn it off
   2. users connect, the connected-users list and the connection history (duration, traffic) work as before
   3. with client-to-client enabled, two clients of the same server can ping each other, and the firewall
      rules page shows a system rule `Allow-OpenVPNRW<N>-client-to-client`
   4. traffic between servers (test 7) still works
   5. speed: run `iperf3` between a client and a LAN host, or between two clients, and compare with DCO off.
      To turn it off on one server:

      ```sh
      uci set openvpn.ns_roadwarrior1.disable_dco=1
      uci commit openvpn
      /etc/init.d/openvpn restart
      ```

      Remove it with `uci delete openvpn.ns_roadwarrior1.disable_dco`, then commit and restart again.
      Without DCO one `openvpn` process uses at most one CPU core: watch it in `top`

Useful commands on the firewall:

```sh
grep -i openvpn /var/log/messages | tail -n 30
api-cli ns.ovpnrw list-instances
uci show users | grep openvpn_
uci show openvpn | grep -E 'ns_inter_server|push'
uci show firewall | grep -E 'inter_server|client_to_client'
ip route
openvpn --version | head -n 1
```

On a client, `route print` (Windows) or `ip route` (Linux) shows the routes received from the server.

## Undo

Before undoing, turn off "Allow traffic with other Road Warrior servers" on all the servers and apply the
changes: the original files don't know the option, so they would leave its routes and firewall rules in place.

```sh
ssh $FW "sh /root/ns-test-backup/install-on-device.sh --restore"
```

This puts back the original files and the original web UI. With DCO installed, it also puts back the original
`openvpn` program, restarts OpenVPN and unloads the module. The users configuration is not restored, because
it may contain users you added during the test; the version from before the first install is
`/root/ns-test-backup/users.config`. The older code keeps working with the converted users.
The client-to-client firewall rules stay: without DCO they are not used.

## Build on Ubuntu

The NethSecurity builder runs on a x86_64 Linux machine, Ubuntu 24.04 for example, also as a virtual
machine. Give it at least 4 CPU cores, 8 GB of RAM (16 GB is better) and 100 GB of free disk space.
The first build downloads and compiles the toolchain and takes a while; the build directories are kept
in podman volumes, so the next builds only compile what changed.

Install the tools, as a normal user (not root):

```sh
sudo apt update
sudo apt install -y git curl python3 podman
podman info > /dev/null && echo "podman works"
```

### DCO files for an official release

This builds only the kernel, OpenVPN with DCO and the `ovpn` kernel module of the official 8.8.0,
about one hour the first time on 4 cores:

```sh
git clone https://github.com/phatdo1819/nethsecurity.git
cd nethsecurity
tools/fork-test/build-dco.sh 8.8.0
```

The result is `ns-dco-8.8.0.tar.gz`. Copy it with step 3 and install it with step 4.

The script builds the sources of the official release, not of this branch, and stops if the kernel built
does not match the official one: the module only loads on the kernel it was built for. For the same reason
the archive fits only that release, so build it again after a system update. The install script skips
it on a different kernel.

### Full image with all the changes

The `ci-fork` branch builds the whole image, web UI included, with DCO:

```sh
git clone -b ci-fork https://github.com/phatdo1819/nethsecurity.git nethsecurity-image
cd nethsecurity-image
./build-nethsec.sh
```

The first build takes a few hours. Afterwards, `git pull` and `./build-nethsec.sh` rebuild only the
changed packages. The image is `bin/targets/x86/64/nethsecurity-*-combined-efi.img.gz`. Install it on the
test firewall keeping the configuration:

```sh
scp bin/targets/x86/64/nethsecurity-*-combined-efi.img.gz root@192.168.1.1:/tmp/
ssh root@192.168.1.1 "sysupgrade -v /tmp/nethsecurity-*-combined-efi.img.gz"
```

The image is built from the development branch of NethSecurity, newer than 8.8.0: use it only on a test
firewall. To go back, install the official image the same way.

## Known limitations

- On an official 8.8.0, the dashboard "Threat Shield" blocked-IP counter shows 0: the new `ns.dashboard`
  reads it from a metric that 8.8.0 does not collect yet. Everything else on the dashboard works.
- Installing a system or package update replaces some of these files with the official version.
  Repeat steps 3 and 4 afterwards, or restore first.
- A reboot does not undo the files, they stay installed.
- The DCO files are built from the official sources with one change: the `ovpn` module contains its own copy
  of the kernel stream parser (used by TCP servers), because the official kernel doesn't have it.
  A full image built from `ci-fork` uses the kernel's one instead.
