---
layout: default
title: WireGuard device binding
parent: Design
---

# WireGuard device binding

**Status:** implemented in the [ns-wgauth](../../packages/ns-wgauth/) package, not released yet. It builds on
[WireGuard user authentication](wireguard_user_auth.md).

* TOC
{:toc}

## Summary

With the login, a peer of a gated server needs its WireGuard key (the `.conf` file), the password of its user and
optionally an OTP code. Whoever has all of them can log in from any machine.

Device binding adds the machine. A gated server can require that its peers log in only from the device enrolled for
them: the device signs every login with a key that never leaves it. A copied `.conf` file, even with the password
and an OTP code, is useless on another machine.

Two layers, both off by default:

1. **Device key**: a P-256 key pair kept by the VPN client, one per tunnel, its private key never exported. The
   firewall records the public key at enrollment and checks a signature of a one-time challenge at every login.
2. **Machine ID** (optional): the client also sends an HMAC of the hardware ID of its machine, recorded at
   enrollment and compared at every login, inside the signed data.

Only a client that implements the protocol below can log in on such a server: the browser and the official WireGuard
apps can't sign. A bound server is for those clients only.

## What it protects against

| Attack | Login only | Device key | Device key and machine ID |
|---|---|---|---|
| `.conf` copied, no password | blocked | blocked | blocked |
| `.conf` and password (and OTP code) used from another machine | **works** | blocked | blocked |
| a copy behind the same public IP while the real user is logged in | **shares the session** | **shares the session** | **shares the session** |
| the private key of the device stolen by an administrator of that machine, used elsewhere | n/a | **works** | blocked, unless the client is modified to send the stolen ID |
| a modified client that sends the ID of the enrolled machine | n/a | needs the key too | needs the key too |
| malware or remote control on the enrolled machine | works | **works**: it uses the key in place | works |

Once the enrolled device has given the peer a WireGuard key of its own, see
[The WireGuard key of the device](#the-wireguard-key-of-the-device), a copy of the `.conf` file gets no handshake at
all: it can't share the session either, even behind the same public IP.

The key is a software key: the client keeps it like the WireGuard private key (encrypted for the system account on
Windows, readable by root only on macOS). A normal user of the machine can't read it; an administrator of the
machine can. Keys in a TPM or a Secure Enclave, which not even an administrator can export, can come later with the
same protocol: the `kind` of the device says where its key is.

The machine ID is not a secret: any user of the machine can read it. It only makes a stolen key harder to use
elsewhere, and tells the administrator which machine logs in.

## Configuration

On the WireGuard server, next to `ns_auth_mode`:

- `ns_device_binding`: `1` to require device binding. Only on a gated server: with `ns_auth_mode` `key` the option
  is removed. A value that isn't a boolean counts as `1`: a typo must not open the gate
- `ns_machine_id`: `1` to require the machine ID too. Only with `ns_device_binding`

In `/etc/config/ns-wgauth`:

- `enroll_window`: seconds the enrollment stays open, default 259200 (72 hours), at most 30 days

## Enrollment

Whoever enrolls first is the device. The enrollment of a peer opens:

- automatically, for `enroll_window` seconds, when the daemon first sees the peer on a bound server: a new peer, new
  keys (`regenerate-peer-keys`), or a server whose binding was just turned on, so existing peers enroll at their next
  login
- when an administrator allows it (`allow-device-enrollment`), for example after a reinstall: the current device is
  forgotten

It closes at the first successful login, with the password and the OTP code: that device is enrolled. A revoked
device (`revoke-device`) leaves the enrollment closed: the peer can't log in until an administrator allows a new one.

If the `.conf` file and the password leak before the real user logs in, the attacker can enroll first. The real
user is then refused with `device_mismatch`, which becomes an alert of the peer, and the enrollment is logged with
the device name and the public IP: the administrator revokes it and generates new keys.

The enrollments are kept by the daemon in `/etc/ns-wgauth/devices.json`, readable by root only, across reboots and
upgrades like the alerts (`/lib/upgrade/keep.d`). Not in UCI: the daemon must not commit UCI, it would commit the
changes the administrator saved but didn't apply. An entry belongs to the WireGuard key of its peer: new keys, or
a removed peer, drop it.

## Login protocol

The login API of [ns-wgauth](wireguard_user_auth.md#login-api) gets a challenge:

1. `GET /api/status` from a peer of a bound server also returns
   `"device": {"required": true, "enrolled": false, "enrollment_open": true, "machine_id": false, "challenge": "..."}`.
   The challenge is 32 random bytes in base64, for that address only, valid 60 seconds and for one login. The
   daemon keeps the latest 4 of each address: the client can ask the status again while it signs.
2. The client signs the message below with ECDSA P-256 and SHA-256, and sends `POST /api/login` with the usual
   fields and

   ```json
   "device": {
     "challenge": "<the challenge>",
     "signature": "<DER signature, base64>",
     "public_key": "<DER SubjectPublicKeyInfo, base64>",
     "kind": "software",
     "name": "LAPTOP-42",
     "machine_id": "<64 hex digits, only when the server asks for it>"
   }
   ```

3. The message is these lines joined by `\n`, without a final newline:

   ```text
   ns-wgauth-device-v1
   <challenge>
   <WireGuard public key of the server>
   <WireGuard public key of the peer>
   <VPN address of the peer>
   <user name, as sent in the login>
   <machine ID, or empty>
   ```

   It ties the signature to one login, one server, one peer and one user name. The key of the peer is the one of
   its `.conf` file, or the WireGuard key the device gave it, see
   [The WireGuard key of the device](#the-wireguard-key-of-the-device): the firewall accepts both.

4. The machine ID is `HMAC-SHA256(key = the 32 bytes of the WireGuard public key of the server, data = the ID in
   lower case)`, in hex: the firewall never sees the raw ID, and two firewalls get different values for the same
   machine. The client reads the ID itself: on Windows the SMBIOS UUID, or `MachineGuid` when the UUID is missing or
   a placeholder; on macOS `IOPlatformUUID`.

The daemon checks the device **before** the password: from another device the password is never checked, so the
page can't be used to guess passwords. Then the password and the OTP code, as without binding. The signatures are
checked with `openssl dgst -verify`: `openssl-util` is already in the image, a Python cryptography library would
add megabytes for one function.

The signature isn't a secret: it travels over the plain HTTP login inside the tunnel without harm, and the challenge
stops a replay.

### Another device with the configuration

WireGuard knows a peer only by its key, so a second device with the same `.conf` completes the handshake: the
firewall can't refuse it before the login. Its handshakes and keepalives take the endpoint of the peer, and the
enrolled device loses the replies meanwhile. So the client of another device must step back at once, before any
login:

- The client asks `GET /api/status?device=<key ID>` right after the tunnel comes up, and then at every status. The
  key ID is the SHA-256 of the DER public key of its device key for the peer, in lower-case hex
  (`device_key_id` in `nethsec.wgauth`), empty when it has no key yet. Without the parameter, from the browser or an
  older client, nothing changes.
- When a device is enrolled, `device` also returns `"this_device": true` or `false`. With `false` the client takes
  the tunnel down, says that the configuration is enrolled on another device, and doesn't reconnect until the user
  turns it on again. The answer is a `device_mismatch` alert of the peer too, at most once an hour.
- The firewall pauses the session of the peer as soon as the status comes from another public IP than the login,
  see [lock_endpoint](wireguard_user_auth.md#sessions), and resumes it when the enrolled device sends again: its
  user doesn't log in again, and the visit isn't counted as a copy (two endpoint changes, the copy detection needs
  three).

The key ID isn't a proof: a modified client can send the ID of the enrolled device, which is public. It gains
nothing, the login still needs the signature, and the paused session doesn't come back until the IP of the login
does. `this_device` only lets an honest client step back.

Errors:

- `403 {"error": "device_required"}`: no `device`, the browser for example. The login page explains it
- `401 {"error": "challenge_expired"}`: unknown, used or expired challenge; the client asks for a new one
- `403 {"error": "device_not_enrolled"}`: no device enrolled and the enrollment is closed
- `401 {"error": "device_mismatch"}`: another key, another machine ID, a missing machine ID or a wrong signature.
  It counts as a failed login for the lockout of the public IP, and becomes a `device_mismatch` alert of the peer,
  at most once an hour

## The WireGuard key of the device

As long as the peer has the WireGuard key of its `.conf` file, every copy of the file completes the handshake: the
login and the device key stop it from logging in, not from connecting, and a copy in the official WireGuard apps
still takes the endpoint of the peer. So after the login the enrolled device gives the peer a WireGuard key of its
own: it makes the key pair, and the private key never leaves it. From then on the firewall accepts only that key for
the peer: the `.conf` file, and every copy of it, gets no handshake at all.

1. A logged-in enrolled device finds `"wireguard_key": "configuration"` in the `device` of `GET /api/status`
   (`"device"` once it gave its key). A client that supports it makes a Curve25519 key pair, and keeps the new
   private key before asking: if the answer is lost, the old key no longer connects and the new one does.
2. It sends `POST /api/device-key`:

   ```json
   {"challenge": "<a challenge of the status>", "wireguard_key": "<the new public key, base64>", "signature": "<DER, base64>"}
   ```

   signed with its device key over these lines joined by `\n`, without a final newline:

   ```text
   ns-wgauth-wireguard-key-v1
   <challenge>
   <WireGuard public key of the server>
   <WireGuard public key of the peer in its .conf file>
   <VPN address of the peer>
   <the new WireGuard public key>
   ```

3. The firewall accepts it only from a peer of a bound server that is logged in (its session open, not paused), with
   an enrolled device whose key signed, and for a key nobody else uses on the firewall: no other peer, device,
   interface or server. WireGuard tells peers apart by their key only: another peer's key would take its place. The
   key the peer has already is accepted again, for a client that missed the answer.
4. `200 {"result": "success"}`. A second later the daemon switches the key on the interface: the answer goes back
   through the tunnel of the old key. The client switches its private key too and connects again; the session goes
   on, it belongs to the address of the peer.

Errors: `401` `not_authenticated` or `challenge_expired`; `403` `device_binding_not_required`, `blocked`,
`device_not_enrolled` or `device_mismatch`; `400` `invalid_key`; `409` `key_in_use`. A refusal is logged.

How the firewall keeps it:

- The key is in the device entry of `devices.json`, `wireguard_key` with `wireguard_key_set`, not in UCI: the daemon
  must not commit the changes the administrator saved but didn't apply. UCI keeps the key of the `.conf` file.
- `wg set <server> peer <old> remove peer <new>` puts it on the interface, with the pre-shared key (through stdin,
  never on the command line), the allowed IPs and the keepalive the kernel has for the peer, found by its reserved IP
  in its allowed IPs (`apply_device_keys` in `nethsec.wgauth`).
- Restarting the interface sets the keys of UCI again, and any change to a peer of the server restarts it
  (`post-commit/restart-wireguard.py`). The hotplug script `/etc/hotplug.d/iface/90-ns-wgauth` runs
  `ns-wgauth keys <server>` when the interface comes up, and the daemon checks the keys at every sync, every
  15 seconds. For those seconds the `.conf` file connects again.
- What WireGuard reports for the key of the device, the handshakes, the endpoints, the `wg-json` of `list-servers`
  and the connection history, is given to the key of the `.conf` file (`to_peer_keys`): the sessions, the alerts,
  the copy detection and the history keep knowing the peer by it. When both keys are there, after a restart, the key
  of the device wins.
- A new enrollment, `allow-device-enrollment` or `revoke-device`, forgets the device and its key, and puts the key of
  the `.conf` file back on the interface at once: the next device enrolls with the file. New keys
  (`regenerate-peer-keys`) drop the device too.

A copy of the `.conf` file still connects before the first enrollment and until the enrolled device gives its key
(whoever enrolls first is the device), and for a few seconds after a restart of the interface. An administrator of
the enrolled machine can copy its WireGuard key, like its device key. The configuration downloaded again from the
firewall doesn't connect either: after a reinstall, allow a new enrollment.

## API

`ns.wireguard`:

- `add-server`, `edit-server`: `device_binding` and `machine_id`, booleans. Missing on edit, they keep their values,
  like the login options. Validation errors: `invalid`; `device_binding` `login_required`; `machine_id`
  `device_binding_required`
- `get-instance-defaults`: `device_binding: true` tells a client the firewall supports it
- `list-servers`: servers return `device_binding` and `machine_id`; the peers of a bound server return `device`:
  `{"state": "enrolled" | "waiting" | "closed"}`, with `enrollment_until` while waiting, and `name`, `kind`,
  `machine_id` (recorded or not), `enrolled`, `last_used`, `from` (public IP of the latest login) and
  `wireguard_key` (`device` or `configuration`, with `wireguard_key_set` for `device`) once enrolled
- `allow-device-enrollment` (`{"id": "...", "hours": 72}`): forgets the device and opens the enrollment, from 1 to
  720 hours. Validation errors: `id` `device_binding_not_required`, `hours` `invalid`
- `revoke-device` (`{"id": "..."}`): forgets the device and ends the session of the peer

Both act at once, like `logout-peer`: they change no UCI option, and put the WireGuard key of the `.conf` file back
on the interface.

`ns-wgauth devices` prints the devices and the open enrollments; `ns-wgauth check` reports a bound server without
`openssl` or without its public key, the peers that can't log in because their enrollment is closed, how many peers
connect with the WireGuard key of their device, and a key that isn't on the interface yet. `ns-wgauth keys [SERVER]`
puts the keys on the interfaces.

## Life cycle

| Event | What happens |
|---|---|
| new peer, new keys | the enrollment opens for `enroll_window` |
| binding turned on | every peer without an entry gets an enrollment window |
| binding turned off, then on | the devices are kept, they work at once |
| login turned off (`key`) | the binding options are removed; the devices stay until the peers get new keys or are removed |
| machine ID turned on after the enrollment | the ID is recorded at the next login of the device |
| reinstall, new machine, lost key | `device_mismatch`; the administrator allows a new enrollment |
| motherboard or VM change, with the machine ID | the same |
| peer or server removed | its entry is dropped at the next `sync` |
| the device gives the peer its WireGuard key | the `.conf` file stops connecting, on every device |
| interface restart | the key of the `.conf` file for a few seconds, then the key of the device again |
| enrollment allowed again, device revoked | the key of the `.conf` file again, at once |

## Alternatives considered

- **Machine ID only**: a fixed value that any user of the machine can read and any modified client can send, and a
  captured login can be replayed. Kept only as a layer on top of the key.
- **Keys in a TPM or a Secure Enclave**: not even an administrator of the machine can export them. Kept for later:
  the macOS Secure Enclave needs a signed app with entitlements, and without attestation the firewall couldn't prove
  where the key is. The protocol already carries `kind`.
- **WebAuthn and passkeys in the browser**: work without a custom client, but need HTTPS with a trusted certificate
  and a domain name, and the login page is plain HTTP inside the tunnel. Synced passkeys aren't tied to one device.
- **Client certificates (mutual TLS)**: HTTPS again, and browsers handle certificates badly.
- **Short-lived WireGuard keys** handed out by the firewall after the login: a bigger change, and the firewall
  would give keys to clients.

## Future work

- keys in the TPM (Windows) and the Secure Enclave (macOS), with attestation
- an approval mode: the first login records the device as pending until an administrator approves it
- proof of presence: the client signs a new challenge every few minutes and the session ends when it stops, which
  would stop a copy behind the same public IP from sharing the session
