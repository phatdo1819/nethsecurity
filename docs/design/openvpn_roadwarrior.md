---
layout: default
title: OpenVPN Road Warrior
parent: Design
---

# OpenVPN Road Warrior

## Multiple instances

The firewall can run more than one Road Warrior server. Each server is an `openvpn` section named `ns_roadwarrior<N>`
tagged with `ns_tag 'automated'`, and it is managed by the `ns.ovpnrw` API.

Each instance is independent and has its own:

- name, the `ns_description` option: it is chosen by the administrator, it is unique and the UI shows it instead of the internal identifier
- listening port: unique among the servers using the same protocol
- network: it can't overlap the network of another server
- network device (`tunrw<N>` or `taprw<N>`) and firewall service (`OpenVPNRW<N>`)
- PKI inside `/etc/openvpn/<instance>/pki`
- connection history database, `/var/openvpn/<instance>/connections.db` (or `/mnt/data/openvpn/<instance>/connections.db` if a storage is configured)

The instance number `<N>` is the lowest one not in use, so it can be reused after an instance has been removed.

The `rwopenvpn` trusted firewall zone is shared by all the instances.

## Users

Each instance uses a users database (`ns_user_db`). Two or more instances can use the same database, so
the same user name and password work on all of them.

A user can belong to more than one instance, the state of each instance is kept inside the `users` configuration:

| Option | Scope | Description |
|---|---|---|
| `openvpn_instances` | per user | list of the instances the user belongs to |
| `openvpn_disabled` | per user | list of the instances where the user is disabled |
| `openvpn_enabled` | per user | `1` if the user is enabled on at least one instance, kept for compatibility |
| `openvpn_ipaddr` | shared | reserved IP address, it is applied only on the instance whose network contains it |
| `openvpn_2fa` | shared | OTP secret |

Adding, enabling, disabling or removing a user always affects a single instance, with these effects:

- the certificate is generated inside the PKI of the instance, the same user has a different certificate for each instance
- removing a user from an instance removes the shared options only if the user does not belong to any other instance
- removing an instance removes it from all the users, the other instances are not affected
- a user can have a single reserved IP: trying to reserve an address of another instance is refused
- deleting a user from its database (`ns.users delete-local-user` or `delete-remote-user`) disconnects it from all
  its instances and revokes its certificates (`nethsec.ovpn.remove_user_access`), so a user with the same name
  can be created and added again later. The revocation is immediate and is not undone by a revert of the
  uncommitted changes: in that case, regenerate the certificates of the user

The authentication and connection scripts (`openvpn-local-auth`, `openvpn-remote-auth`, `openvpn-otp-auth`,
`01-check-status`) allow the connection only if `nethsec.ovpn.is_user_enabled` is true for the instance.

### Upgrade from previous releases

Before the support of multiple instances, `openvpn_enabled` was the only flag. Users without `openvpn_instances`
are considered legacy users: they belong to all the instances using their database, if `openvpn_enabled` is `1`.
The `99_ns-openvpn-user-instances` uci-defaults script converts them to explicit membership at the first boot,
so the access does not change after the upgrade.

## Connection history

The `connection-history` and `connection-history-csv` methods of `ns.ovpnrw` work on a single instance,
or on all the instances if the `instance` parameter is omitted. In the second case the databases are attached
in read-only mode and queried together: every row contains the `instance` field.

SQLite attaches at most 10 databases per connection, so the aggregated history includes the first 10 instances only.

## Related code

- `packages/ns-api/files/ns.ovpnrw`: API
- `packages/python3-nethsec/src/nethsec/ovpn/__init__.py`: shared helpers, including the instance membership
- `packages/ns-openvpn/`: authentication, connection and disconnection scripts
