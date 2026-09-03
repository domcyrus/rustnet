<p align="center"><strong>English</strong> | <a href="SERVICE.zh-CN.md">简体中文</a> | <a href="SERVICE.ja.md">日本語</a></p>

# Headless Service Guide

RustNet can run continuously under the native service manager on Linux, macOS,
Windows, and FreeBSD, or under Docker Compose. Installing RustNet or one of the
included service definitions does not enable or start monitoring. Review the
command and retention policy, then activate the service explicitly.

Running `rustnet` without options always starts the interactive TUI. Every
service definition in this repository passes `--headless` explicitly and uses
a 5000 ms refresh interval to limit long-running CPU and storage use. The CLI
default remains 500 ms.

## Security, output, and retention

Packet capture needs elevated privileges on most systems. The systemd,
launchd, and rc.d definitions start as root so RustNet can initialize capture,
then RustNet applies its normal sandbox and privilege reduction. The Windows
service runs as LocalSystem and depends on Npcap. Docker adds only `NET_RAW`,
drops all other Linux capabilities, and uses host networking.

Connection snapshots can contain process names, addresses, hostnames, and
traffic metadata. Keep their parent directory private and grant access only to
operators who should see that information.

The service defaults are:

| Platform | Snapshot output | Diagnostics | Included retention |
|---|---|---|---|
| Linux systemd | `/var/lib/rustnet/headless.jsonl` | systemd journal | Daily rotation, 7 files, compression |
| macOS launchd | `/var/db/rustnet/headless.jsonl` | `/var/db/rustnet/headless.err.log` | None |
| Windows SCM | `%ProgramData%\Rustnet\rustnet.jsonl` | Service status through SCM | None |
| FreeBSD rc.d | `/var/db/rustnet/headless.jsonl` | `/var/db/rustnet/headless.err.log` | None |
| Docker Compose | Container stdout | Container stderr | Docker `json-file`, 10 MB times 7 files |

Linux uses `copytruncate` so RustNet can keep its output descriptor open during
rotation. Configure local rotation before long-running macOS, Windows, or
FreeBSD use. Stop the service before moving or replacing an active output file.
Removing a service definition does not remove captured data. Delete retained
files separately only when they are no longer needed.

For a custom headless command, `--output-file FILE` writes snapshots directly
to a securely opened regular file instead of stdout. With `--output jsonl`, a
new run appends to the file. With `--output json`, a new run replaces the file
with its single final snapshot. `--output-file`, `--output`, `--duration`, and
`--filter` all require `--headless`.

```bash
# Append a versioned snapshot stream
sudo rustnet --headless --output jsonl --output-file /var/lib/rustnet/custom.jsonl

# Replace the file with one final snapshot after 60 seconds
sudo rustnet --headless --duration 60 --output json --output-file /var/lib/rustnet/final.json
```

## Linux with systemd

The unit expects RustNet at `/usr/bin/rustnet`. Distribution packages can place
the included files automatically. For a manual installation from this source
tree:

```bash
sudo install -m 0755 target/release/rustnet /usr/bin/rustnet
sudo install -Dm0644 resources/packaging/linux/systemd/rustnet-headless.service \
  /etc/systemd/system/rustnet-headless.service
sudo install -Dm0644 resources/packaging/linux/systemd/rustnet-headless.env \
  /etc/default/rustnet-headless
sudo install -Dm0644 resources/packaging/linux/logrotate/rustnet-headless \
  /etc/logrotate.d/rustnet-headless
sudo systemctl daemon-reload
```

In a binary release archive, run these commands from the extracted directory
and replace `target/release/rustnet` with `./rustnet`.

These commands install an inactive unit. Configure optional filters or other
arguments in `/etc/default/rustnet-headless`. The fixed `--headless`,
`--interface any`, `--refresh-interval 5000`, and `--output jsonl` arguments
cannot be removed through that file.

```bash
# Enable at boot, then start now
sudo systemctl enable rustnet-headless.service
sudo systemctl start rustnet-headless.service

# Inspect status, diagnostics, and snapshots
systemctl status rustnet-headless.service
sudo journalctl -u rustnet-headless.service -f
sudo tail -F /var/lib/rustnet/headless.jsonl

# Stop and disable
sudo systemctl stop rustnet-headless.service
sudo systemctl disable rustnet-headless.service
```

To uninstall a manual definition, stop and disable it first, then remove only
the installed definition files:

```bash
sudo rm /etc/systemd/system/rustnet-headless.service
sudo rm /etc/default/rustnet-headless
sudo rm /etc/logrotate.d/rustnet-headless
sudo systemctl daemon-reload
```

The private `/var/lib/rustnet` state directory and its snapshots remain in
place. Use the package manager instead when the files came from a package.

## macOS with launchd

The launchd property list expects the release app at `/Applications/Rustnet.app`
and runs `/Applications/Rustnet.app/Contents/MacOS/rustnet`. Install the app
bundle there, then run the included installer:

```bash
sudo /Applications/Rustnet.app/Contents/Resources/service/launchd/install-rustnet-headless.sh
```

For a CLI or binary-archive installation, install `rustnet` at a stable
absolute path and pass it explicitly to the copy under
`resources/packaging/macos/launchd`:

```bash
sudo install -m 0755 rustnet /usr/local/bin/rustnet
sudo env RUSTNET_BIN=/usr/local/bin/rustnet \
  resources/packaging/macos/launchd/install-rustnet-headless.sh
```

The installer creates `/var/db/rustnet` with mode `0700`, installs
`com.domcyrus.rustnet-headless.plist`, disables the job, and does not bootstrap
or start it. Enable and load it only when ready. Because the property list uses
`RunAtLoad`, bootstrapping also starts monitoring.

```bash
# Enable and start
sudo launchctl enable system/com.domcyrus.rustnet-headless
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/com.domcyrus.rustnet-headless.plist

# Inspect status, diagnostics, and snapshots
sudo launchctl print system/com.domcyrus.rustnet-headless
sudo tail -F /var/db/rustnet/headless.err.log
sudo tail -F /var/db/rustnet/headless.jsonl

# Restart an already loaded job
sudo launchctl kickstart -k system/com.domcyrus.rustnet-headless

# Stop, unload, and disable
sudo launchctl bootout system/com.domcyrus.rustnet-headless
sudo launchctl disable system/com.domcyrus.rustnet-headless
```

To uninstall the definition after booting it out:

```bash
sudo rm /Library/LaunchDaemons/com.domcyrus.rustnet-headless.plist
```

The app bundle and `/var/db/rustnet` data remain until removed separately.

## Windows with the Service Control Manager

Install Npcap with its standard options first, then install the RustNet MSI from
an Administrator PowerShell:

```powershell
msiexec.exe /i .\rustnet-<version>.msi
```

The MSI registers the `Rustnet` service with Manual startup. It does not start
the service or configure automatic startup. Its command contains
`--windows-service --headless --output jsonl --output-file
"%ProgramData%\Rustnet\rustnet.jsonl" --refresh-interval 5000`. The internal
`--windows-service` switch is for SCM activation only. Continue to use bare
`rustnet` for the TUI.

```powershell
# Optionally enable automatic startup, then start now
Set-Service -Name Rustnet -StartupType Automatic
Start-Service -Name Rustnet

# Inspect status and follow snapshots
Get-Service -Name Rustnet
sc.exe queryex Rustnet
Get-Content "$env:ProgramData\Rustnet\rustnet.jsonl" -Wait

# Inspect SCM lifecycle errors in the System event log
Get-WinEvent -LogName System |
  Where-Object ProviderName -eq 'Service Control Manager' |
  Where-Object Message -Match 'Rustnet' |
  Select-Object -First 20

# Stop and disable
Stop-Service -Name Rustnet
Set-Service -Name Rustnet -StartupType Disabled
```

Uninstall through Windows Settings, or use the same MSI from an Administrator
PowerShell:

```powershell
msiexec.exe /x .\rustnet-<version>.msi
```

The installer stops and removes the service. Retained files under
`%ProgramData%\Rustnet` may remain and should be removed separately if desired.

## FreeBSD with rc.d

The rc.d script expects RustNet at `/usr/local/bin/rustnet`. Install the binary,
then run the included definition installer:

```sh
sudo install -m 0555 target/release/rustnet /usr/local/bin/rustnet
sudo resources/packaging/freebsd/rc.d/install-rustnet-headless.sh
```

In a binary release archive, replace `target/release/rustnet` with `./rustnet`.

The installer creates `/var/db/rustnet` with mode `0700`, installs
`rustnet_headless`, and keeps `rustnet_headless_enable=NO`.

```sh
# Enable at boot, then start now
sudo sysrc rustnet_headless_enable=YES
sudo service rustnet_headless start

# Inspect status, diagnostics, and snapshots
sudo service rustnet_headless status
sudo tail -F /var/db/rustnet/headless.err.log
sudo tail -F /var/db/rustnet/headless.jsonl

# Stop and disable
sudo service rustnet_headless stop
sudo sysrc rustnet_headless_enable=NO
```

Set optional CLI arguments with `rustnet_headless_extra_args` in `/etc/rc.conf`.
The script always retains its explicit `--headless --refresh-interval 5000
--output jsonl` arguments.

To uninstall the manual definition:

```sh
sudo rm /usr/local/etc/rc.d/rustnet_headless
sudo sysrc -x rustnet_headless_enable
sudo sysrc -x rustnet_headless_extra_args
```

The binary and `/var/db/rustnet` data remain until removed separately.

## Docker Compose

The included Compose file builds the existing image and overrides its command
with explicit headless arguments. Building or pulling an image does not start
monitoring.

```bash
# Build without starting
docker compose -f compose.headless.yml build

# Start explicitly
docker compose -f compose.headless.yml up -d

# From a binary release archive, use its semver without the leading v
RUSTNET_IMAGE_TAG=VERSION docker compose -f compose.headless.yml pull
RUSTNET_IMAGE_TAG=VERSION docker compose -f compose.headless.yml up -d --no-build

# Inspect status and output
docker compose -f compose.headless.yml ps
docker compose -f compose.headless.yml logs -f rustnet

# Stop without removing the container, then uninstall the deployment
docker compose -f compose.headless.yml stop
docker compose -f compose.headless.yml down
```

Compose has no separate install or enable step. Building the image prepares the
deployment, and `down` removes its container and network. After the first explicit start, the
`restart: unless-stopped` policy restarts the container after failures or a
Docker daemon restart unless an operator stopped it. The snapshot stream stays
on container stdout, and Docker applies the included bounded log policy.

To persist snapshots as files instead, add a private host volume, pass
`--output-file` in `command`, and configure host-side rotation. Keep the output
path writable inside the read-only container without adding broader
capabilities.
