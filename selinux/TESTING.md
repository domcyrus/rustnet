# Fedora SELinux Test Plan

Use a Fedora VM for enforcement testing. Containers can verify that the module
builds, but they do not provide a clean SELinux policy store, file labelling,
domain transition, and audit-log environment independent from the host.

## VM Setup

Target the same Fedora releases enabled in COPR, currently Fedora 42 and 43.

```bash
sudo dnf install \
  audit clang elfutils-libelf-devel libpcap-devel llvm make rust cargo \
  policycoreutils policycoreutils-python-utils selinux-policy-devel setools-console

getenforce
sestatus
```

`getenforce` should report `Enforcing`.

## Build And Install Policy

From the rustnet checkout:

```bash
make -C selinux
sudo semodule -i selinux/rustnet.pp
sudo restorecon -v /usr/bin/rustnet

semodule -l | grep rustnet
ls -Z /usr/bin/rustnet
```

The first policy contains `permissive rustnet_t;`, so it logs policy gaps without
blocking the application.

## Confirm Domain Transition

```bash
rustnet --help >/dev/null
ps -eZ | grep rustnet || true
```

For a short-lived command, use `runcon` to inspect the domain directly:

```bash
runcon -t rustnet_t -- id -Z
```

## Real Capture Smoke Test

Run a real capture session for at least five minutes:

```bash
rustnet
```

Exercise:

- default reverse DNS lookups;
- `--no-resolve-dns`;
- `--log-level debug`;
- `--pcap-export /tmp/rustnet-test.pcap`;
- GeoIP databases under `/usr/share/GeoIP/` if available.

When retesting output paths after a policy update, remove files/directories from
previous permissive runs first so SELinux type transitions apply at creation
time:

```bash
rm -rf logs /tmp/rustnet-test.pcap /tmp/rustnet-test.pcap.connections.jsonl
```

Review AVCs:

```bash
sudo ausearch -m avc -ts recent
```

## Enforcing Trial

Only after the permissive AVCs have been reviewed, remove this line from
`selinux/rustnet.te`:

```selinux
permissive rustnet_t;
```

Rebuild and reinstall:

```bash
make -C selinux clean
make -C selinux
sudo semodule -i selinux/rustnet.pp
sudo restorecon -v /usr/bin/rustnet
```

Repeat the smoke test and verify that expected rustnet workflows still work.
Collect any new AVCs with:

```bash
sudo ausearch -m avc -ts recent
```

## Non-Goals

The RPM must not install firewalld or nftables rules. Subnet-level egress policy
is administrator-managed and outside this SELinux module.
