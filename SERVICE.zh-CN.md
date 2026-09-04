<p align="center"><a href="SERVICE.md">English</a> | <strong>简体中文</strong> | <a href="SERVICE.ja.md">日本語</a></p>

# Linux 无界面服务示例

RustNet 软件包仅将 systemd 单元作为文档示例提供。安装或升级软件包不会注册、
启用、启动或重启此服务。管理员必须主动复制并配置示例。本文适用于 systemd
246 或更新版本以及 Linux 5.8 或更新内核，不安装 Windows、macOS 或 FreeBSD 服务。

示例捕获 Linux 的所有网络接口，每五秒写入一条带版本号的 JSONL 快照。这些
是最新状态快照，并非完整的连接事件历史。输出出现背压时可能跳过中间快照。
参见[无界面 schema](https://github.com/domcyrus/rustnet/blob/main/USAGE.zh-CN.md#headless-mode)。独立的 `--json-log`
参数记录连接事件，不保存 stdout 快照。

## 安装和启用

根据安装来源找到示例：

| 安装来源 | 示例单元路径 |
| --- | --- |
| 发布版 DEB 或 RPM | `/usr/share/doc/rustnet-monitor/examples/rustnet-headless.service` |
| Debian 源码包或 PPA | `/usr/share/doc/rustnet/examples/rustnet-headless.service` |
| 原生 RPM 包 | `/usr/share/doc/rustnet/rustnet-headless.service` |
| openSUSE RPM 包 | `/usr/share/doc/packages/rustnet/rustnet-headless.service` |
| Linux 发布归档或源码目录 | `resources/packaging/linux/systemd/rustnet-headless.service` |

在解压的 Linux 归档或源码目录中运行：

```bash
sudo install -m 0644 resources/packaging/linux/systemd/rustnet-headless.service \
  /etc/systemd/system/rustnet-headless.service
# 如果二进制不在 /usr/bin/rustnet，请修改 ExecStart。
sudo systemctl edit --full rustnet-headless.service
sudo systemd-analyze verify /etc/systemd/system/rustnet-headless.service
sudo install -d -m 0700 -o root -g root /var/lib/rustnet
sudo systemctl daemon-reload
sudo systemctl enable --now rustnet-headless.service
sudo systemctl status rustnet-headless.service
```

首次启动前必须主动创建该目录，因为 systemd 可能先打开 stdout，再准备
`StateDirectory`。使用软件包时，将首条命令中的源路径替换为对应的示例路径。
不要使用管理员的交互式账户运行服务。单元会清除 `SUDO_UID`、`SUDO_GID` 和 `SUDO_USER`，
以 root 打开抓包和 eBPF 资源，然后由 RustNet 在解析流量之前降权到 `nobody`。
如果身份切换失败，启动会在解析流量之前中止；请检查 journal 日志了解原因。
仅授予抓包、eBPF 初始化和身份切换所需的 capabilities，不授予 `CAP_SYS_ADMIN`。
如果 eBPF 不可用，降权后的 procfs 回退只能看到有限的进程信息；依赖进程归属
之前，请检查快照中的进程检测方式。

单元保持 RustNet 沙箱开启，除私有状态目录和临时存储外，将文件系统设为只读，
并隐藏用户主目录。如需自定义配置或 GeoIP 数据库，请放在合适的系统目录中并
配置明确路径。不要为使输出路径可写而关闭沙箱或扩大目录访问权限。

## 输出、关闭和保留

systemd 在降权前打开 `/var/lib/rustnet/headless.jsonl`。其父目录由 root
所有，权限为 `0700`；新输出文件权限为 `0600`。进程仅保留打开的 stdout
描述符。诊断信息单独写入 journal，因此大型快照行不会被 journal 拆分，诊断
文本也不会破坏 JSONL 数据流。

```bash
# 分别查看快照和诊断信息。
sudo tail -n 1 /var/lib/rustnet/headless.jsonl | jq .
sudo journalctl -u rustnet-headless.service -n 50
# SIGTERM 请求有时限的关闭并写入最终记录。
sudo systemctl stop rustnet-headless.service
```

快照可能包含敏感的网络和进程元数据。请限制访问、监控剩余磁盘空间，并选择
保留策略。重启时会追加输出，不会自动轮转。若要避免截断正在写入的记录，先
停止服务，在私有目录内重命名文件，再启动服务。这会产生短暂的监控间隙：

```bash
sudo systemctl stop rustnet-headless.service
sudo mv /var/lib/rustnet/headless.jsonl \
  /var/lib/rustnet/headless-$(date +%Y%m%d-%H%M%S).jsonl
sudo systemctl start rustnet-headless.service
```

不要使用 `copytruncate` 来保证无损保留，也不要通过 SIGHUP 重新打开文件：
SIGHUP 会停止无界面监控。软件包升级不会修改管理员复制的单元。请检查更新后
的示例，并在二进制升级后主动重启。卸载 RustNet 前，运行
`sudo systemctl disable --now rustnet-headless.service`，删除复制的单元，
然后执行 `sudo systemctl daemon-reload`。私有抓包数据会保留，直到主动删除。

## 不分配终端的 Docker 运行方式

在 Linux 主机上，现有镜像可直接输出快照，无需 `-t` 或 `-i`：

```bash
umask 077
docker run --rm --name rustnet-headless --net=host --stop-timeout 30 \
  ghcr.io/domcyrus/rustnet:latest \
  --headless --interface any --refresh-interval 5000 --output jsonl \
  > headless.jsonl
```

调用命令的 shell 会创建私有输出文件，无需将可写的主机目录挂载到容器中。
stderr 仍单独显示。在另一终端运行 `docker stop rustnet-headless` 会发送
SIGTERM，并等待最多 30 秒写入最终输出。Docker Desktop 的主机网络不具有
与原生 Linux 相同的主机抓包语义。

默认镜像使用非 root 用户，并通过 `CAP_NET_RAW` 抓包。仅使用主机网络不会
暴露主机进程身份。启用 eBPF 或查看主机进程需要额外权限；扩大访问范围之前，
请阅读 [Docker 安装指南](https://github.com/domcyrus/rustnet/blob/main/INSTALL.zh-CN.md#using-docker)。Docker 日志驱动
可能限制记录大小和保留时间。如需精确的 JSONL 数据流，请使用上述 stdout
重定向，并管理输出文件的存储和保留策略。
