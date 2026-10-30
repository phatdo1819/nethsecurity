# NethSecurity

> [!WARNING]
> **This is a personal fork, and its changes are a proof of concept.** It isn't the official NethSecurity: Nethesis
> didn't make or review these changes and doesn't support them. They were written by an AI (Claude, by Anthropic),
> directed and tested by one person on test firewalls, and no security expert has reviewed them. Don't install the
> images of this fork on a firewall you rely on. For the official firewall, see
> [NethServer/nethsecurity](https://github.com/NethServer/nethsecurity).
>
> What the fork adds, each with a guide to test it:
> - **OpenVPN Road Warrior with several servers**: branch `feat/ovpnrw-multi-instance`, test images from `ci-fork`,
>   [FORK-TESTING.md](https://github.com/phatdo1819/nethsecurity/blob/feat/ovpnrw-multi-instance/FORK-TESTING.md).
> - **A login for WireGuard servers** (`ns-wgauth`): the peers log in on a web page, with the password of a local
>   user and an optional authenticator code, before their traffic passes; with device binding, fallback addresses,
>   connection history and one peer per user. Branch `feat/wireguard-user-auth`, test images from `ci-wgauth`,
>   [WGAUTH-TESTING.md](https://github.com/phatdo1819/nethsecurity/blob/ci-wgauth/WGAUTH-TESTING.md).

### The WireGuard login

With made-up names and documentation addresses, not a real firewall.

| | |
| --- | --- |
| ![A server with the login: its login page, fallback address and device binding; each peer with its user, connection, login state and device, one of them blocked as a suspected copy](screenshots/wireguard-server.png) | ![The login settings of a server: WireGuard key only, key and password, or key, password and OTP; the users database, the session length, device binding](screenshots/wireguard-server-login.png) |
| A server that requires the login: who is connected, logged in, and from which device. A configuration used from two places at once blocks its peer. | Its settings: the key alone, or also a password and an OTP code; the users database, the session length, device binding. |
| ![The peer of alice: the users that already have a peer on this server are greyed out](screenshots/wireguard-peer-user.png) | ![The connection history: each connection of the peers of the servers, its user, addresses, length and traffic](screenshots/wireguard-connections.png) |
| A peer is linked to a user, one peer per user on a server. | The connection history of the servers, recorded from the handshakes. |

The login page, here on a phone. On a server without device binding (here "Contractors"), the peers log in with any
browser, as with the official WireGuard apps. With device binding (Head office), only the app enrolled on the device
can log in, and the page says so.

<img src="screenshots/login-page.png" alt="The login page of a server without device binding: username, password and OTP code" width="240"> <img src="screenshots/login-page-done.png" alt="The same page once logged in: when the session ends" width="240"> <img src="screenshots/login-page-device.png" alt="The login page of a server with device binding: a web browser can't log in, only the VPN app on the enrolled device" width="240">

---

The rest of this page is the README of the official project.

[![License](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](https://opensource.org/licenses/GPL-2.0)
[![Build Status](https://github.com/NethServer/nethsecurity/actions/workflows/build-image.yml/badge.svg)](https://github.com/NethServer/nethsecurity/actions/workflows/build-image.yml)
[![Documentation Status](https://img.shields.io/badge/docs-stable-brightgreen.svg)](https://docs.nethsecurity.org/)
[![Community](https://img.shields.io/badge/community-forum-orange.svg)](https://community.nethserver.org/)

NethSecurity is an Open Source Linux firewall, a downstream rebuild of [OpenWrt](https://openwrt.org/).
It's the successor of [NethServer 7 firewall suite](https://docs.nethserver.org/).

## Purpose

NethSecurity provides a robust, secure, and manageable firewall solution for networks of all sizes, with a focus on ease of use and flexibility.
It is primarily designed for x86_64 machines, though support for other architectures may be added in the future.

## Installation

See the [installation guide](https://docs.nethsecurity.org/en/latest/install.html) for detailed instructions.

## Further documentation

Screenshots and more information at the :point_right: [official site](https://www.nethsecurity.org/).

To get started with NethSecurity, check out the [Administrator manual](https://docs.nethsecurity.org/). :book:

:hammer_and_wrench: If you are a developer, you can find useful information inside the [Developer manual](https://dev.nethsecurity.org/)
and the [Developer handbook](https://handbook.nethserver.org/).

## Support requests

:ring_buoy: For support requests and questions, please use the [community forum](https://community.nethserver.org/).

## Reporting bugs

:heavy_exclamation_mark: Before reporting a new issue, discuss it on [community.nethserver.org](https://community.nethserver.org).

See the [CONTRIBUTING.md](.github/CONTRIBUTING.md) file for more details.

