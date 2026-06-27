# Fedora SELinux Policy

This directory contains the Fedora SELinux policy module used by the COPR RPM.
It targets modern Fedora only and is intentionally installed in permissive mode
for the first iteration. That lets maintainers collect AVCs from real capture
sessions before turning the domain enforcing.

## Scope

- Label `/usr/bin/rustnet` as `rustnet_exec_t`.
- Transition normal Fedora interactive sessions from `unconfined_t` into
  `rustnet_t`.
- Permit the capabilities rustnet needs for packet capture and eBPF setup.
- Permit DNS name resolution and the expected read-only runtime data.
- Avoid firewalld/nftables integration. Subnet-level egress policy remains an
  administrator choice outside the RPM.

## Build Locally

```bash
sudo dnf install selinux-policy-devel make
make -C selinux
```

## Manual Install

```bash
sudo semodule -i selinux/rustnet.pp
sudo restorecon -v /usr/bin/rustnet
```

## AVC Review

Run rustnet normally, then inspect recent AVCs:

```bash
sudo ausearch -m avc -ts recent
```

When the policy is clean on supported Fedora releases, remove the
`permissive rustnet_t;` rule from `rustnet.te` in a follow-up change.

For end-to-end enforcement testing, use a Fedora VM rather than a container.
See [TESTING.md](TESTING.md).
