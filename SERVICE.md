<p align="center"><strong>English</strong> | <a href="SERVICE.zh-CN.md">简体中文</a> | <a href="SERVICE.ja.md">日本語</a></p>

# Linux headless service example

RustNet packages include a systemd unit as documentation only. Installing or
upgrading a package does not register, enable, start, or restart this service.
An administrator must copy and configure the example explicitly. This guide
covers Linux with systemd 246 or newer and a Linux 5.8 or newer kernel. It does
not install Windows, macOS, or FreeBSD services.

The example captures all Linux interfaces and writes one versioned JSONL
snapshot every five seconds. These are latest-value snapshots, not a complete
connection-event history. Under output backpressure, intermediate snapshots
can be skipped. See the [headless schema](https://github.com/domcyrus/rustnet/blob/main/USAGE.md#headless-mode). The separate
`--json-log` option records connection events; it does not save stdout snapshots.

## Install and enable

Locate the example shipped by your installation:

| Installation | Example unit |
| --- | --- |
| Release DEB or RPM | `/usr/share/doc/rustnet-monitor/examples/rustnet-headless.service` |
| Debian source package or PPA | `/usr/share/doc/rustnet/examples/rustnet-headless.service` |
| Native RPM package | `/usr/share/doc/rustnet/rustnet-headless.service` |
| openSUSE RPM package | `/usr/share/doc/packages/rustnet/rustnet-headless.service` |
| Linux release archive or source checkout | `resources/packaging/linux/systemd/rustnet-headless.service` |

From the extracted Linux archive or source checkout:

```bash
sudo install -m 0644 resources/packaging/linux/systemd/rustnet-headless.service \
  /etc/systemd/system/rustnet-headless.service
# Adjust ExecStart if the binary is not installed at /usr/bin/rustnet.
sudo systemctl edit --full rustnet-headless.service
sudo systemd-analyze verify /etc/systemd/system/rustnet-headless.service
sudo install -d -m 0700 -o root -g root /var/lib/rustnet
sudo systemctl daemon-reload
sudo systemctl enable --now rustnet-headless.service
sudo systemctl status rustnet-headless.service
```

The explicit directory creation is required before the first start because
systemd can open stdout before preparing `StateDirectory`. For a package
installation, substitute its example path in the first command.
Do not run the service as an interactive administrator account. The unit clears
`SUDO_UID`, `SUDO_GID`, and `SUDO_USER`, opens capture and eBPF resources as root,
and lets RustNet drop to `nobody` before parsing traffic. If this identity change
fails, startup aborts before traffic parsing; inspect the journal for the cause.
It grants only capture,
eBPF setup, and identity-drop capabilities, with no `CAP_SYS_ADMIN`. If eBPF is
unavailable, procfs fallback after the drop has limited process visibility;
inspect the snapshot's process detection method before relying on attribution.
`AmbientCapabilities=CAP_SETUID` preserves the intended UID-drop permission
through systemd's seccomp setup, including systemd 255. RustNet clears ambient
capabilities before changing identity; this does not widen the bounding set.

The unit keeps RustNet's sandbox enabled and makes the filesystem read-only
except for its private state directory and temporary storage. Home directories
are hidden. If you need custom configuration or GeoIP databases, place them in
an appropriate system location and configure explicit paths. Do not disable the
sandbox or widen directory permissions to make an output path writable.

## Output, shutdown, and retention

systemd opens `/var/lib/rustnet/headless.jsonl` before the privilege drop. Its
parent directory is root-owned with mode `0700`; new output files use mode
`0600`. The process retains only the open stdout descriptor. Diagnostics go to
the journal separately. Large snapshot lines therefore avoid journal line
splitting, and diagnostic text cannot corrupt the JSONL stream.

```bash
# Inspect snapshots and diagnostics separately.
sudo tail -n 1 /var/lib/rustnet/headless.jsonl | jq .
sudo journalctl -u rustnet-headless.service -n 50
# SIGTERM requests a bounded shutdown and a final record.
sudo systemctl stop rustnet-headless.service
```

Snapshots can contain sensitive network and process metadata. Limit access,
monitor available disk space, and choose a retention policy. Output appends
across restarts and is not rotated automatically. To rotate without truncating
an active record, stop the service, rename the file inside its private directory,
then start it again. This introduces a short monitoring gap:

```bash
sudo systemctl stop rustnet-headless.service
sudo mv /var/lib/rustnet/headless.jsonl \
  /var/lib/rustnet/headless-$(date +%Y%m%d-%H%M%S).jsonl
sudo systemctl start rustnet-headless.service
```

Do not use `copytruncate` for lossless retention, and do not send SIGHUP to
reopen the file: SIGHUP stops headless monitoring. Package upgrades leave the
administrator's copied unit untouched. Review updated examples and restart
explicitly after a binary upgrade. Before uninstalling RustNet, run
`sudo systemctl disable --now rustnet-headless.service`, remove the copied unit,
and run `sudo systemctl daemon-reload`. Private captured data is retained until
you deliberately remove it.

## Docker without a terminal

On a Linux host, the existing image can stream snapshots without `-t` or `-i`:

```bash
umask 077
docker run --rm --name rustnet-headless --net=host --stop-timeout 30 \
  ghcr.io/domcyrus/rustnet:latest \
  --headless --interface any --refresh-interval 5000 --output jsonl \
  > headless.jsonl
```

The invoking shell creates a private output file; no writable host directory
needs to be mounted into the container. stderr remains visible separately.
From another terminal, `docker stop rustnet-headless` sends SIGTERM and allows
up to 30 seconds for final output. Docker Desktop host networking does not
provide the same host capture semantics as native Linux.

The default image uses a non-root user with `CAP_NET_RAW` for capture. Host
networking alone does not expose host process identities. Enabling eBPF or host
process visibility requires additional permissions; review the
[Docker installation guide](https://github.com/domcyrus/rustnet/blob/main/INSTALL.md#using-docker) before expanding access.
Docker logging drivers may impose their own record-size and retention limits.
For an exact JSONL stream, use the attached stdout redirection shown above and
manage the resulting file's storage and retention.
