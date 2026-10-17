# Security Policy

## What this software is

Parental Gateway is a **network gateway appliance**. It runs with `NET_ADMIN`,
manipulates `iptables`, forwards traffic and — when web filtering is enabled —
intercepts DNS for every device on your LAN. Treat it with the same care you
would give your router.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ |

## Reporting a vulnerability

Please open a **private security advisory** on GitHub rather than a public
issue:

https://github.com/Thorinas112/parental-gateway/security/advisories/new

Include a description, the version you are running, reproduction steps and the
impact you expect. I will acknowledge within a few days and aim to ship a fix
for anything serious within a week.

Please **do not** include real device MAC addresses, IP addresses, hostnames or
your own credentials in a report — redacted examples are fine.

## Deployment hardening

Before exposing the web interface beyond your own machine:

- [ ] Complete the setup wizard immediately — while it is pending, whoever
      reaches `/setup` first claims the administrator account.
- [ ] Use a long random `SECRET_KEY` so sessions survive container rebuilds.
- [ ] Set `SESSION_COOKIE_SECURE=1` if you terminate TLS in front of the app.
- [ ] Restrict port 8080 to your LAN subnet at the firewall.
- [ ] Keep `./data` backed up and not world-readable — it holds the database
      and the session signing key.
- [ ] Keep the host patched and the image rebuilt regularly.

## Known limitations

These are design constraints, not vulnerabilities, but they are worth
understanding before you rely on the system:

- **MAC filtering is not a security boundary.** A MAC address can be cloned.
  It is the right tool for a family network, not for a hostile one.
- **DNS filtering filters DNS, not content.** Encrypted DNS (DoH/DoT) and VPNs
  bypass it, and it cannot see paths within a permitted domain. Use it as one
  layer, not the only layer.
- **Enforcement only applies to traffic that routes through the gateway.**
  A device configured with some other default route is not filtered.
- **The setup wizard is unauthenticated by design.** It must be, since there is
  no account yet. Complete it promptly.

## Scope

This project is intended for hardware you own or administer. Deploying it on a
network you do not control, or using it to monitor people without their
knowledge, is out of scope and not something I can help with.
