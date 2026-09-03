<p align="center"><a href="SERVICE.md">English</a> | <strong>简体中文</strong> | <a href="SERVICE.ja.md">日本語</a></p>

# 无界面服务指南

RustNet 可以由 Linux、macOS、Windows 和 FreeBSD 的原生服务管理器持续运行，也可以
由 Docker Compose 管理。安装 RustNet 或仓库提供的服务定义不会启用或启动监控。请先
检查命令与数据保留策略，再明确启用服务。

不带参数运行 `rustnet` 始终会启动交互式 TUI。仓库中的每个服务定义都会显式传入
`--headless`，并使用 5000 ms 的刷新间隔，以降低长期运行时的 CPU 与存储开销。
命令行的默认刷新间隔仍为 500 ms。

## 安全、输出与数据保留

大多数系统上的数据包捕获都需要提升权限。systemd、launchd 和 rc.d 定义会以 root
启动，让 RustNet 初始化捕获，随后 RustNet 会照常启用沙箱并降低权限。Windows 服务
以 LocalSystem 身份运行，并依赖 Npcap。Docker 仅添加 `NET_RAW`，丢弃其他所有 Linux
capability，并使用主机网络。

连接快照可能包含进程名、地址、主机名和流量元数据。请确保父目录仅对需要查看这些
信息的管理员开放。

各服务的默认设置如下：

| 平台 | 快照输出 | 诊断信息 | 内置保留策略 |
|---|---|---|---|
| Linux systemd | `/var/lib/rustnet/headless.jsonl` | systemd journal | 每日轮换，保留 7 份并压缩 |
| macOS launchd | `/var/db/rustnet/headless.jsonl` | `/var/db/rustnet/headless.err.log` | 无 |
| Windows SCM | `%ProgramData%\Rustnet\rustnet.jsonl` | 通过 SCM 查看服务状态 | 无 |
| FreeBSD rc.d | `/var/db/rustnet/headless.jsonl` | `/var/db/rustnet/headless.err.log` | 无 |
| Docker Compose | 容器 stdout | 容器 stderr | Docker `json-file`，10 MB × 7 份 |

Linux 使用 `copytruncate`，轮换期间 RustNet 可以继续持有输出描述符。长期运行 macOS、
Windows 或 FreeBSD 服务前，请配置本机轮换策略。移动或替换正在使用的输出文件前，
应先停止服务。删除服务定义不会删除已捕获的数据，仅在不再需要时另行删除保留文件。

对于自定义无界面命令，`--output-file FILE` 会把快照直接写入安全打开的普通文件，而
不是 stdout。使用 `--output jsonl` 时，新一轮运行会追加到文件；使用 `--output json`
时，新一轮运行会以唯一的最终快照替换文件。`--output-file`、`--output`、`--duration`
和 `--filter` 都必须与 `--headless` 一起使用。

```bash
# 追加带版本号的快照流
sudo rustnet --headless --output jsonl --output-file /var/lib/rustnet/custom.jsonl

# 运行 60 秒后，以一份最终快照替换文件
sudo rustnet --headless --duration 60 --output json --output-file /var/lib/rustnet/final.json
```

## Linux systemd

unit 默认要求 RustNet 位于 `/usr/bin/rustnet`。发行版软件包可自动安装这些文件。若要
从本源码树手动安装：

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

若使用二进制发行归档，请在解压后的目录中运行这些命令，并将
`target/release/rustnet` 替换为 `./rustnet`。

以上命令只会安装未激活的 unit。可在 `/etc/default/rustnet-headless` 中配置可选过滤器
或其他参数。该文件不能移除固定的 `--headless`、`--interface any`、
`--refresh-interval 5000` 与 `--output jsonl` 参数。

```bash
# 启用开机启动，然后立即启动
sudo systemctl enable rustnet-headless.service
sudo systemctl start rustnet-headless.service

# 查看状态、诊断信息和快照
systemctl status rustnet-headless.service
sudo journalctl -u rustnet-headless.service -f
sudo tail -F /var/lib/rustnet/headless.jsonl

# 停止并禁用
sudo systemctl stop rustnet-headless.service
sudo systemctl disable rustnet-headless.service
```

卸载手动安装的定义时，请先停止并禁用服务，再仅删除已安装的定义文件：

```bash
sudo rm /etc/systemd/system/rustnet-headless.service
sudo rm /etc/default/rustnet-headless
sudo rm /etc/logrotate.d/rustnet-headless
sudo systemctl daemon-reload
```

私有的 `/var/lib/rustnet` 状态目录及其中的快照会保留。若这些文件来自软件包，请改用
对应的软件包管理器卸载。

## macOS launchd

launchd plist 默认要求发行版 app 位于 `/Applications/Rustnet.app`，并运行
`/Applications/Rustnet.app/Contents/MacOS/rustnet`。先把 app bundle 安装到该路径，
再运行仓库提供的安装脚本：

```bash
sudo /Applications/Rustnet.app/Contents/Resources/service/launchd/install-rustnet-headless.sh
```

若使用命令行或二进制归档版本，请把 `rustnet` 安装到稳定的绝对路径，并将该路径显式
传给 `resources/packaging/macos/launchd` 中的脚本：

```bash
sudo install -m 0755 rustnet /usr/local/bin/rustnet
sudo env RUSTNET_BIN=/usr/local/bin/rustnet \
  resources/packaging/macos/launchd/install-rustnet-headless.sh
```

安装脚本会以 `0700` 权限创建 `/var/db/rustnet`，安装
`com.domcyrus.rustnet-headless.plist`，禁用任务，并且不会 bootstrap 或启动。准备完成后
再启用和加载。由于 plist 使用 `RunAtLoad`，bootstrap 也会启动监控。

```bash
# 启用并启动
sudo launchctl enable system/com.domcyrus.rustnet-headless
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/com.domcyrus.rustnet-headless.plist

# 查看状态、诊断信息和快照
sudo launchctl print system/com.domcyrus.rustnet-headless
sudo tail -F /var/db/rustnet/headless.err.log
sudo tail -F /var/db/rustnet/headless.jsonl

# 重启已加载的任务
sudo launchctl kickstart -k system/com.domcyrus.rustnet-headless

# 停止、卸载并禁用
sudo launchctl bootout system/com.domcyrus.rustnet-headless
sudo launchctl disable system/com.domcyrus.rustnet-headless
```

bootout 完成后，可卸载服务定义：

```bash
sudo rm /Library/LaunchDaemons/com.domcyrus.rustnet-headless.plist
```

app bundle 和 `/var/db/rustnet` 数据会继续保留，需另行删除。

## Windows Service Control Manager

先按默认选项安装 Npcap，再在管理员 PowerShell 中安装 RustNet MSI：

```powershell
msiexec.exe /i .\rustnet-<version>.msi
```

MSI 会以“手动”启动类型注册 `Rustnet` 服务，不会启动服务或配置自动启动。服务命令
包含 `--windows-service --headless --output jsonl --output-file
"%ProgramData%\Rustnet\rustnet.jsonl" --refresh-interval 5000`。内部参数
`--windows-service` 仅供 SCM 激活使用。需要 TUI 时仍直接运行 `rustnet`。

```powershell
# 可选：启用自动启动，然后立即启动
Set-Service -Name Rustnet -StartupType Automatic
Start-Service -Name Rustnet

# 查看状态并持续读取快照
Get-Service -Name Rustnet
sc.exe queryex Rustnet
Get-Content "$env:ProgramData\Rustnet\rustnet.jsonl" -Wait

# 在 System 事件日志中查看 SCM 生命周期错误
Get-WinEvent -LogName System |
  Where-Object ProviderName -eq 'Service Control Manager' |
  Where-Object Message -Match 'Rustnet' |
  Select-Object -First 20

# 停止并禁用
Stop-Service -Name Rustnet
Set-Service -Name Rustnet -StartupType Disabled
```

可通过 Windows 设置卸载，也可以在管理员 PowerShell 中使用同一个 MSI：

```powershell
msiexec.exe /x .\rustnet-<version>.msi
```

安装程序会停止并移除服务。`%ProgramData%\Rustnet` 中的保留文件可能继续存在，如有
需要请另行删除。

## FreeBSD rc.d

rc.d 脚本默认要求 RustNet 位于 `/usr/local/bin/rustnet`。先安装二进制文件，再运行
仓库提供的定义安装脚本：

```sh
sudo install -m 0555 target/release/rustnet /usr/local/bin/rustnet
sudo resources/packaging/freebsd/rc.d/install-rustnet-headless.sh
```

若使用二进制发行归档，请将 `target/release/rustnet` 替换为 `./rustnet`。

安装脚本会以 `0700` 权限创建 `/var/db/rustnet`，安装 `rustnet_headless`，并保持
`rustnet_headless_enable=NO`。

```sh
# 启用开机启动，然后立即启动
sudo sysrc rustnet_headless_enable=YES
sudo service rustnet_headless start

# 查看状态、诊断信息和快照
sudo service rustnet_headless status
sudo tail -F /var/db/rustnet/headless.err.log
sudo tail -F /var/db/rustnet/headless.jsonl

# 停止并禁用
sudo service rustnet_headless stop
sudo sysrc rustnet_headless_enable=NO
```

可在 `/etc/rc.conf` 中通过 `rustnet_headless_extra_args` 设置可选 CLI 参数。脚本始终
保留显式的 `--headless --refresh-interval 5000 --output jsonl` 参数。

卸载手动安装的定义：

```sh
sudo rm /usr/local/etc/rc.d/rustnet_headless
sudo sysrc -x rustnet_headless_enable
sudo sysrc -x rustnet_headless_extra_args
```

二进制文件和 `/var/db/rustnet` 数据会继续保留，需另行删除。

## Docker Compose

仓库提供的 Compose 文件会构建现有镜像，并用显式无界面参数覆盖镜像命令。构建或
拉取镜像不会启动监控。

```bash
# 仅构建，不启动
docker compose -f compose.headless.yml build

# 显式启动
docker compose -f compose.headless.yml up -d

# 使用二进制发行归档时，将 VERSION 替换为不带开头 v 的语义版本号
RUSTNET_IMAGE_TAG=VERSION docker compose -f compose.headless.yml pull
RUSTNET_IMAGE_TAG=VERSION docker compose -f compose.headless.yml up -d --no-build

# 查看状态与输出
docker compose -f compose.headless.yml ps
docker compose -f compose.headless.yml logs -f rustnet

# 停止但保留容器，然后卸载部署
docker compose -f compose.headless.yml stop
docker compose -f compose.headless.yml down
```

Compose 没有独立的安装或启用步骤。构建镜像会准备部署，`down` 会移除容器和网络。
首次明确启动后，`restart: unless-stopped` 策略会在容器
失败或 Docker daemon 重启后重新启动容器，除非管理员已停止它。快照流写入容器
stdout，并由 Docker 执行内置的有界日志策略。

若要把快照持久化到文件，请添加私有的主机 volume，在 `command` 中传入
`--output-file`，并配置主机侧轮换。只需让输出路径在只读容器中可写，不要增加更广泛
的 capability。
