<p align="center"><a href="INSTALL.md">English</a> | <strong>简体中文</strong></p>

# 安装指南

本文档涵盖 RustNet 在各平台上的所有安装方法。

## 目录

- [从发布包安装](#installing-from-release-packages)
  - [macOS DMG 安装](#macos-dmg-installation)
  - [Windows MSI 安装](#windows-msi-installation)
  - [Windows Chocolatey 安装](#windows-chocolatey-installation)
  - [Linux 包安装](#linux-package-installation)
  - [FreeBSD 安装](#freebsd-installation)
  - [Android（Termux）安装](#android-termux-installation)
- [通过 Cargo 安装](#install-via-cargo)
- [从源码构建](#building-from-source)
- [使用 Docker](#using-docker)
- [前置要求](#prerequisites)
- [权限配置](#permissions-setup)
- [GeoIP 数据库（可选）](#geoip-databases-optional)
- [故障排查](#troubleshooting)

## 从发布包安装<a id="installing-from-release-packages"></a>

预构建包可在每个版本的 [GitHub Releases](https://github.com/domcyrus/rustnet/releases) 页面下载。

### macOS DMG 安装<a id="macos-dmg-installation"></a>

> **更喜欢 Homebrew？** 如果你已安装 Homebrew，使用 `brew install` 更简单，且无需绕过 Gatekeeper 步骤。参见 [Homebrew 安装](#homebrew-installation)了解详情。

1. **下载**适合你架构的 DMG：
   - Apple Silicon Mac（M1/M2/M3）使用 `Rustnet_macOS_AppleSilicon.dmg`
   - Intel Mac 使用 `Rustnet_macOS_Intel.dmg`

2. **打开 DMG** 并将 Rustnet.app 拖拽到 Applications 文件夹

3. **绕过 Gatekeeper**（针对未签名构建）：
   - 首次尝试打开 RustNet 时，macOS 会阻止它，因为应用未签名
   - 前往 **系统设置 → 隐私与安全性**
   - 向下滚动找到 RustNet 被阻止的消息
   - 点击 **"仍要打开"** 以允许应用运行
   - 再次启动应用时可能需要确认此选择

4. **运行 RustNet**：
   - 双击 Rustnet.app 以在带 sudo 的终端窗口中启动
   - 或从命令行运行：`sudo /Applications/Rustnet.app/Contents/MacOS/rustnet`

5. **可选：创建 shell 访问的符号链接**：
   ```bash
   # 创建符号链接，以便在任何位置运行 'rustnet'
   sudo ln -s /Applications/Rustnet.app/Contents/MacOS/rustnet /usr/local/bin/rustnet

   # 现在你可以从任何终端运行：
   sudo rustnet
   ```

6. **可选：配置 BPF 权限**（以避免需要 sudo）：
   - 安装 Wireshark 的 BPF 权限助手：`brew install --cask wireshark-chmodbpf`
   - 注销并重新登录以使组变更生效
   - 详细说明参见[权限配置](#permissions-setup)章节

### Windows MSI 安装<a id="windows-msi-installation"></a>

1. **安装 Npcap Runtime**（包捕获必需）：
   - 从 https://npcap.com/dist/ 下载
   - 运行安装程序并选择 **"WinPcap API compatible mode"**

2. **下载并安装**适合的 MSI 包：
   - 64 位 Windows 使用 `Rustnet_Windows_64-bit.msi`
   - 32 位 Windows 使用 `Rustnet_Windows_32-bit.msi`

3. **运行安装程序**并按照安装向导操作

4. **运行 RustNet**：
   - 打开命令提示符或 PowerShell
   - 运行：`rustnet.exe`
   - 如果未安装 Npcap 或未处于 WinPcap 兼容模式，RustNet 会显示一条有用的错误消息及安装说明
   - 注意：根据你的 Npcap 安装设置，你可能需要或不需要 Administrator 特权

### Windows Chocolatey 安装<a id="windows-chocolatey-installation"></a>

在 Windows 上安装 RustNet 最简单的方式是通过 [Chocolatey](https://community.chocolatey.org/packages/rustnet)：

```powershell
# 在 Administrator PowerShell 中运行
choco install rustnet
```

**注意：** 你仍需要单独安装 [Npcap](https://npcap.com)，并启用 "WinPcap API compatible mode"。

### Linux 包安装<a id="linux-package-installation"></a>

#### Ubuntu PPA（推荐用于 Ubuntu 25.10 Questing 和 26.04 LTS Resolute）

在 Ubuntu 上安装 RustNet 最简单的方式是通过官方 PPA。该 PPA 为以下 Ubuntu 系列发布构建：

- Ubuntu 25.10（Questing Quokka）
- Ubuntu 26.04 LTS（Resolute Raccoon）

```bash
# 添加 RustNet PPA
sudo add-apt-repository ppa:domcyrus/rustnet

# 更新包列表
sudo apt update

# 安装 rustnet
sudo apt install rustnet

# 使用 sudo 运行
sudo rustnet

# 可选：授予 Linux capabilities 以无需 sudo 运行（现代内核 5.8+）
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/bin/rustnet
rustnet
```

**重要：** 该 PPA 仅支持上述两个系列（Ubuntu 25.10 Questing 和 26.04 LTS Resolute），因为构建需要 Rust 1.88+（项目中使用了 let-chains）。早期 Ubuntu 版本的仓库中没有足够新的 `rustc`。对于旧版 Ubuntu，请使用 GitHub releases 中的 [.deb 包](#debianubuntu-deb-packages)或[从源码构建](#building-from-source)。

#### Debian/Ubuntu（.deb 包）<a id="debianubuntu-deb-packages"></a>

用于手动安装或非 Ubuntu 的 Debian 系发行版：

```bash
# 下载适合你架构的包：
# - Rustnet_LinuxDEB_amd64.deb（x86_64）
# - Rustnet_LinuxDEB_arm64.deb（ARM64）
# - Rustnet_LinuxDEB_armhf.deb（ARMv7）

# 安装包（Linux capabilities 会自动配置）
sudo dpkg -i Rustnet_LinuxDEB_amd64.deb

# 如有需要安装依赖
sudo apt-get install -f

# 无需 sudo 运行（post-install 脚本已设置 Linux capabilities）
rustnet

# 验证 Linux capabilities
getcap /usr/bin/rustnet
```

**注意：** .deb 包通过 post-install 脚本自动设置 Linux capabilities，因此你可以无需 sudo 运行 RustNet。

#### RedHat/Fedora/CentOS（.rpm 包）<a id="redhatfedoracentos-rpm-packages"></a>

用于手动安装或不使用 COPR 的发行版：

```bash
# 下载适合你架构的包：
# - Rustnet_LinuxRPM_x86_64.rpm
# - Rustnet_LinuxRPM_aarch64.rpm

# 安装包（Linux capabilities 会自动配置）
sudo rpm -i Rustnet_LinuxRPM_x86_64.rpm
# 或使用 dnf/yum：
sudo dnf install Rustnet_LinuxRPM_x86_64.rpm

# 无需 sudo 运行（post-install 脚本已设置 Linux capabilities）
rustnet

# 验证 Linux capabilities
getcap /usr/bin/rustnet
```

**注意：** .rpm 包通过 post-install 脚本自动设置 Linux capabilities，因此你可以无需 sudo 运行 RustNet。

#### Arch Linux

该包已包含在 Arch Linux Extra 仓库中（[链接](https://archlinux.org/packages/extra/x86_64/rustnet/)）。可使用 pacman 安装：
```bash
sudo pacman -S rustnet
```

此外，还有两个 AUR 包可用：
- [`rustnet-bin`](https://aur.archlinux.org/packages/rustnet-bin) —— 来自 GitHub Releases 的预编译二进制文件
- [`rustnet-git`](https://aur.archlinux.org/packages/rustnet-git) —— 从源码构建并使用最新提交（由 [@DeepChirp](https://github.com/DeepChirp) 维护）

使用你喜欢的 AUR 助手安装：
```bash
# 来自 GitHub Releases 的预编译二进制文件
yay -S rustnet-bin

# 或使用最新提交的源码构建
yay -S rustnet-git
```

#### Fedora（COPR - 推荐用于 Fedora 42+）<a id="fedora-copr---recommended-for-fedora-42"></a>

在 Fedora 上安装 RustNet 最简单的方式是通过官方 COPR 仓库。

```bash
# 启用 COPR 仓库
sudo dnf copr enable domcyrus/rustnet

# 安装 rustnet
sudo dnf install rustnet

# 使用 sudo 运行
sudo rustnet

# 可选：授予 Linux capabilities 以无需 sudo 运行（现代内核 5.8+）
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/bin/rustnet
rustnet
```

**重要：** 由于 Rust 1.88+ 的要求，COPR 仅支持 Fedora 42 和 43。CentOS 和 RHEL 的仓库中没有足够新的 Rust 编译器。对于这些发行版，请使用 GitHub releases 中的 [.rpm 包](#redhatfedoracentos-rpm-packages)或[从源码构建](#building-from-source)。

#### Homebrew 安装<a id="homebrew-installation"></a>

**在 macOS 上：**
```bash
brew tap domcyrus/rustnet
brew install rustnet

# 按照安装后显示的提示进行权限配置
```

**在 Linux 上：**
```bash
brew install domcyrus/rustnet/rustnet

# 为 Homebrew 安装的二进制文件授予 Linux capabilities（现代内核 5.8+）
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' $(brew --prefix)/bin/rustnet

# 无需 sudo 运行
rustnet
```

#### 静态二进制文件（可移植 - 任意 Linux 发行版）<a id="static-binary-portable---any-linux-distribution"></a>

为获得最大可移植性，静态二进制文件可在**任意 Linux 发行版**上运行，不受 GLIBC 版本限制。它们完全自包含，不需要任何系统依赖。

```bash
# 下载适合你架构的静态二进制文件：
# - rustnet-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz（x86_64）
# - rustnet-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz（ARM64）

# 解压归档
tar xzf rustnet-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz

# 将二进制文件移动到 PATH
sudo mv rustnet-vX.Y.Z-x86_64-unknown-linux-musl/rustnet /usr/local/bin/

# 授予 Linux capabilities（现代内核 5.8+）
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/local/bin/rustnet

# 无需 sudo 运行
rustnet
```

**何时使用静态二进制文件：**
- GLIBC 过时的旧发行版（例如 CentOS 7、旧版 Ubuntu）
- 最小化/容器化环境
- 难以安装依赖的气隙系统
- 当你需要一个单一的可移植二进制文件时

### FreeBSD 安装<a id="freebsd-installation"></a>

FreeBSD 支持从版本 0.15.0 开始提供。

#### 从 Ports 或 Packages（未来）<a id="from-ports-or-packages-future"></a>

一旦进入 FreeBSD ports：
```bash
# 使用 pkg（二进制包）
pkg install rustnet

# 或从 ports 构建
cd /usr/ports/net/rustnet && make install clean
```

#### 从 GitHub Releases<a id="from-github-releases"></a>

从 [rustnet-bsd releases](https://github.com/domcyrus/rustnet-bsd/releases) 下载 FreeBSD 二进制文件：

```bash
# 下载适合的包
fetch https://github.com/domcyrus/rustnet-bsd/releases/download/vX.Y.Z/rustnet-vX.Y.Z-x86_64-unknown-freebsd.tar.gz

# 解压归档
tar xzf rustnet-vX.Y.Z-x86_64-unknown-freebsd.tar.gz

# 将二进制文件移动到 PATH
sudo mv rustnet-vX.Y.Z-x86_64-unknown-freebsd/rustnet /usr/local/bin/

# 使其可执行
sudo chmod +x /usr/local/bin/rustnet

# 使用 sudo 运行
sudo rustnet
```

#### 在 FreeBSD 上从源码构建<a id="building-from-source-on-freebsd"></a>

```bash
# 安装依赖
pkg install rust libpcap

# 克隆仓库
git clone https://github.com/domcyrus/rustnet.git
cd rustnet

# Release 模式构建
cargo build --release

# 可执行文件位于 target/release/rustnet
sudo ./target/release/rustnet
```

#### FreeBSD 权限配置<a id="permission-setup-for-freebsd"></a>

FreeBSD 需要访问 BPF（Berkeley Packet Filter）设备来进行数据包捕获。

**选项 1：使用 sudo 运行（最简单）**
```bash
sudo rustnet
```

**选项 2：将用户添加到 bpf 组（推荐）**
```bash
# 将你的用户添加到 bpf 组
sudo pw groupmod bpf -m $(whoami)

# 注销并重新登录以使组变更生效

# 现在无需 sudo 运行
rustnet
```

**选项 3：更改 BPF 设备权限（临时）**
```bash
# 重启后会重置
sudo chmod o+rw /dev/bpf*

# 现在无需 sudo 运行
rustnet
```

**验证 FreeBSD 权限：**
```bash
# 检查是否在 bpf 组中
groups | grep bpf

# 检查 BPF 设备权限
ls -la /dev/bpf*

# 不使用 sudo 测试
rustnet --help
```

### Android（Termux）安装<a id="android-termux-installation"></a>

RustNet 可以通过 [Termux](https://termux.dev/en/) 在 Android 设备上运行，前提是设备已 root。

由于 Android 严格控制网络和进程信息，RustNet 需要 `root` 访问权限（`su`）才能捕获数据包和识别进程。提供一个专门的 Android 构建，静态链接依赖并禁用与 Android 内核环境不兼容的 Linux 特定功能（如 eBPF 和 Landlock）。

#### 前置要求
1. **已 Root** 的 Android 设备（例如通过 Magisk 或 KernelSU）
2. 已安装 **Termux**（从 F-Droid 或 GitHub 获取，*不要*从 Google Play 获取）

#### 安装步骤

1. **在 Termux 中安装所需包：**
   ```bash
   pkg update
   pkg install tsu wget tar
   ```

2. **下载 Android 二进制文件：**
   ```bash
   # 从 GitHub Releases 下载 Android 专用静态二进制文件
   wget https://github.com/domcyrus/rustnet/releases/download/vX.Y.Z/rustnet-vX.Y.Z-aarch64-linux-android-musl.tar.gz
   ```

3. **解压并安装：**
   ```bash
   tar xzf rustnet-vX.Y.Z-aarch64-linux-android-musl.tar.gz
   
   # 将其移动到 PATH 中的目录
   mv rustnet-vX.Y.Z-aarch64-linux-android-musl/rustnet $PREFIX/bin/
   chmod +x $PREFIX/bin/rustnet
   ```

4. **以 root 身份运行 RustNet：**
   ```bash
   # 你必须以 root 权限运行 RustNet，才能在 Android 上正常工作
   sudo rustnet
   ```
   *注意：首次运行时，你的 root 管理器（例如 Magisk）会提示你授予 Termux Superuser 访问权限。*

## 通过 Cargo 安装<a id="install-via-cargo"></a>

```bash
# 直接从 crates.io 安装
cargo install rustnet-monitor

# 二进制文件将安装到 ~/.cargo/bin/rustnet
# 确保 ~/.cargo/bin 在你的 PATH 中
```

安装后，参见[权限配置](#permissions-setup)章节配置权限。

## 从源码构建<a id="building-from-source"></a>

### 前置要求<a id="prerequisites"></a>

- Rust 2024 edition 或更高版本（从 [rustup.rs](https://rustup.rs/) 安装）
- 平台特定依赖：
  - **Linux（Debian/Ubuntu）**：
    ```bash
    sudo apt-get install build-essential pkg-config libpcap-dev libelf-dev zlib1g-dev clang llvm
    ```
  - **Linux（RedHat/CentOS/Fedora）**：
    ```bash
    sudo yum install make pkgconfig libpcap-devel elfutils-libelf-devel zlib-devel clang llvm
    ```
  - **macOS**：安装 Xcode Command Line Tools：`xcode-select --install`
  - **FreeBSD**：`pkg install rust libpcap`
  - **Windows**：安装 Npcap 和 Npcap SDK（参见下方的 [Windows 构建配置](#windows-build-setup)）

### 基本构建

```bash
# 克隆仓库
git clone https://github.com/domcyrus/rustnet.git
cd rustnet

# Release 模式构建（Linux 上默认启用 eBPF）
cargo build --release

# 构建不带 eBPF 支持（仅 Linux procfs 模式）
cargo build --release --no-default-features

# 可执行文件位于 target/release/rustnet
```

不带 eBPF（仅 procfs 模式）构建时，使用 `cargo build --release --no-default-features`。

### Windows 构建配置<a id="windows-build-setup"></a>

在 Windows 上构建 RustNet 需要 Npcap SDK 和正确的环境配置：

#### 构建需求

1. **下载并安装 Npcap SDK**：
   - 从 https://npcap.com/dist/ 下载 Npcap SDK
   - 将 SDK 解压到一个目录（例如 `C:\npcap-sdk`）

2. **设置环境变量**：
   - 将 `LIB` 环境变量设置为包含 SDK 的库路径：
     ```cmd
     set LIB=%LIB%;C:\npcap-sdk\Lib\x64
     ```
   - 对于 PowerShell：
     ```powershell
     $env:LIB = "$env:LIB;C:\npcap-sdk\Lib\x64"
     ```
   - 要永久设置，请添加到你的系统环境变量中

3. **构建 RustNet**：
   ```cmd
   cargo build --release
   ```

#### 运行时需求

1. **安装 Npcap Runtime**：
   - 从 https://npcap.com/dist/ 下载 Npcap 安装程序
   - 运行安装程序并在安装期间**选择 "WinPcap API compatible mode"**
   - 这确保与包捕获库的兼容性

2. **运行 RustNet**：
   ```cmd
   rustnet.exe
   ```

**注意**：根据你的 Npcap 安装设置，你可能需要或不需要 Administrator 特权。如果你在 Npcap 安装期间没有选择限制数据包捕获到管理员的选项，RustNet 可以用普通用户权限运行。

## 使用 Docker<a id="using-docker"></a>

RustNet 可作为 Docker 容器从 GitHub Container Registry 获取：

```bash
# 拉取最新镜像
docker pull ghcr.io/domcyrus/rustnet:latest

# 或拉取特定版本
docker pull ghcr.io/domcyrus/rustnet:0.7.0

# 使用 eBPF 支持所需的 Linux capabilities 运行（latest）
docker run --rm -it --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON --net=host \
  ghcr.io/domcyrus/rustnet:latest

# 使用特定版本运行
docker run --rm -it --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON --net=host \
  ghcr.io/domcyrus/rustnet:0.7.0

# 使用指定接口运行
docker run --rm -it --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON --net=host \
  ghcr.io/domcyrus/rustnet:latest -i eth0

# 替代方案：使用 privileged 模式（安全性较低但更简单）
docker run --rm -it --privileged --net=host \
  ghcr.io/domcyrus/rustnet:latest

# 查看可用选项
docker run --rm ghcr.io/domcyrus/rustnet:latest --help
```

**注意：** 容器需要 Linux capabilities（`NET_RAW`、`BPF` 和 `PERFMON`）或 privileged 模式才能进行带 eBPF 支持的数据包捕获。推荐使用主机网络（`--net=host`）以监控所有网络接口。

## 权限配置<a id="permissions-setup"></a>

RustNet 需要提升的特权来捕获网络数据包，因为在所有现代操作系统上，访问网络接口进行数据包捕获是一项特权操作。本章节解释如何在不同平台上正确授予这些权限。

> ### **安全优势：Linux 上的只读网络访问**
>
> **RustNet 在所有平台上使用只读数据包捕获，不启用混杂模式。** 这意味着：
>
> **Linux：** 仅需要 **`CAP_NET_RAW`** 这项 Linux capability —— **不需要**完整的 root 或 `CAP_NET_ADMIN`
> **最小权限原则：** 数据包捕获所需的最小权限
> **无混杂模式：** 仅捕获往返于主机的数据包（而非所有网络流量）
> **只读：** 不能修改或注入数据包
> **增强安全性：** 与完整 root 访问相比，攻击面更小
>
> **macOS 注意：** PKTAP（用于进程元数据）需要 root 特权，但你可以在不使用 sudo 的情况下运行，使用 `lsof` 回退进行基本数据包捕获。

### 为什么需要权限<a id="why-permissions-are-required"></a>

网络数据包捕获需要访问：

- **Raw socket** 用于低层网络访问（只读、非混杂模式）
- **网络接口** 用于数据包捕获
- macOS/BSD 系统上的 **BPF（Berkeley Packet Filter）设备**
- 某些 Linux 配置上的 **网络命名空间**

这些 Linux capabilities 受到限制，以防止恶意软件拦截网络流量。

### macOS 权限配置<a id="macos-permission-setup"></a>

在 macOS 上，数据包捕获需要访问位于 `/dev/bpf*` 的 BPF（Berkeley Packet Filter）设备。

**注意：** macOS PKTAP（用于从数据包中提取进程元数据）需要 **root/sudo** 特权。不使用 sudo 时，RustNet 使用 `lsof` 作为进程检测的回退（较慢，但无需 root）。

#### 选项 1：使用 sudo 运行（最简单）

```bash
# 使用 sudo 构建并运行
cargo build --release
sudo ./target/release/rustnet
```

#### 选项 2：BPF 组访问（推荐）

将用户添加到 `access_bpf` 组以实现免密码数据包捕获：

**使用 Wireshark 的 ChmodBPF（用于基本数据包捕获）：**

```bash
# 安装 Wireshark 的 BPF 权限助手
brew install --cask wireshark-chmodbpf

# 注销并重新登录以使组变更生效
# 然后无需 sudo 运行 rustnet：
rustnet  # 使用 lsof 进行进程检测（较慢）

# 如需 PKTAP 支持以从包头部获取进程元数据，请使用 sudo：
sudo rustnet  # 使用 PKTAP 进行更快的进程检测
```

**注意**：`wireshark-chmodbpf` 授予对 `/dev/bpf*` 的数据包捕获访问权限，但 **PKTAP** 是一个独立的特权内核接口，无论 BPF 权限如何都需要 root 特权。TUI 会显示当前使用的检测方法（使用 sudo 时为 "pktap"，不使用 sudo 时为 "lsof"）。

**手动 BPF 组配置：**

```bash
# 创建 access_bpf 组（如果不存在）
sudo dseditgroup -o create access_bpf

# 将用户添加到组中
sudo dseditgroup -o edit -a $USER -t user access_bpf

# 设置 BPF 设备权限（每次重启后都需要执行）
sudo chmod g+rw /dev/bpf*
sudo chgrp access_bpf /dev/bpf*

# 注销并重新登录以使组成员身份生效
```

#### 选项 3：Homebrew 安装

如果通过 Homebrew 安装，formula 会提供详细的配置说明：

```bash
brew tap domcyrus/rustnet
brew install rustnet
# 按照安装后显示的提示操作
```

### Linux 权限配置（只读访问 - 无需 Root！）<a id="linux-permission-setup-read-only-access---no-root-required"></a>

**Linux 优势：** RustNet 进行数据包捕获**仅需要 `CAP_NET_RAW`** —— 远少于完整的 root 访问！

在 Linux 上，数据包捕获仅需要 `CAP_NET_RAW` 这项 Linux capability，用于只读、非混杂数据包捕获。对于 eBPF 增强型进程追踪，需要额外的 Linux capabilities（`CAP_BPF` 和 `CAP_PERFMON`），但**不需要 `CAP_NET_ADMIN`**。

#### 选项 1：使用 sudo 运行（最简单）

```bash
# 使用 sudo 构建并运行
cargo build --release
sudo ./target/release/rustnet
```

#### 选项 2：授予 Linux capabilities（推荐）

为二进制文件授予特定的 Linux capabilities，而无需完整的 root 特权：

**对于源码构建：**

```bash
# 先构建二进制文件
cargo build --release

# 为二进制文件授予 Linux capabilities（现代内核 5.8+，带 eBPF 支持）
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' ./target/release/rustnet

# 现在无需 sudo 运行
./target/release/rustnet
```

**对于 cargo 安装的二进制文件：**

```bash
# 如果通过 cargo install rustnet-monitor 安装（现代内核 5.8+）
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' ~/.cargo/bin/rustnet

# 现在无需 sudo 运行
rustnet
```

**对于启用 eBPF 的构建（增强型 Linux 性能 - 默认启用）：**

eBPF 在 Linux 构建上默认启用，使用内核探针提供低开销的进程识别：

```bash
# Release 模式构建（默认启用 eBPF）
cargo build --release

# 现代 Linux（5.8+）- 仅需这三个 Linux capabilities：
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' ./target/release/rustnet
./target/release/rustnet

# 旧版 Linux（无 CAP_BPF 的旧内核）- 使用 CAP_SYS_ADMIN 作为回退：
sudo setcap 'cap_net_raw,cap_sys_admin+eip' ./target/release/rustnet
./target/release/rustnet

# 检查 TUI 统计面板 - 应显示 "Process Detection: eBPF + procfs"
```

**Linux capabilities 需求：**

**基础 Linux capabilities（始终需要）：**
- `CAP_NET_RAW` —— 用于只读数据包捕获的 raw socket 访问（非混杂模式）

**eBPF 所需的 Linux capabilities（根据内核版本选择）：**

**现代 Linux（5.8+）：**
- `CAP_BPF` —— BPF 程序加载和 map 操作
- `CAP_PERFMON` —— 性能监控和追踪操作

**旧版 Linux（pre-5.8）：**
- `CAP_SYS_ADMIN` —— 在没有 CAP_BPF 支持的老内核上进行 BPF 操作所需

**注意：** 不需要 CAP_NET_ADMIN。RustNet 使用不带混杂模式的只读数据包捕获。

**回退行为**：如果 eBPF 无法加载（例如 Linux capabilities 不足、内核不兼容），应用会自动使用仅 procfs 模式。TUI 统计面板显示当前使用的检测方法：
- `Process Detection: eBPF + procfs` —— eBPF 成功加载
- `Process Detection: procfs` —— 使用 procfs 回退

**注意：** eBPF 在 Linux 构建上默认启用，进程名显示可能存在局限性。有关 eBPF 实现的详情参见 [ARCHITECTURE.zh-CN.md](ARCHITECTURE.zh-CN.md)。要构建不带 eBPF 的版本，使用 `cargo build --release --no-default-features`。

**对于系统级安装：**

```bash
# 如果通过包管理器安装或复制到 /usr/local/bin（现代内核 5.8+）
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/local/bin/rustnet
rustnet
```

### Windows 权限配置<a id="windows-permission-setup"></a>

Windows 支持目前有限，但可用时：

- RustNet 需要 **Administrator 特权**
- 必须安装 **WinPcap** 或 **Npcap** 用于数据包捕获
- 以 Administrator 身份运行命令提示符或 PowerShell

### 验证权限<a id="verifying-permissions"></a>

要验证权限是否正确配置：

#### macOS

```bash
# 检查 BPF 设备权限
ls -la /dev/bpf*

# 检查组成员身份
groups | grep access_bpf

# 不使用 sudo 测试
rustnet --help
```

#### Linux

```bash
# 检查二进制文件上的 Linux capabilities
# 对于源码构建：
getcap ./target/release/rustnet

# 对于 cargo 安装的二进制文件：
getcap ~/.cargo/bin/rustnet

# 对于系统级安装：
getcap $(which rustnet)

# 现代（5.8+）：应显示 cap_net_raw,cap_bpf,cap_perfmon+eip
# 旧版：应显示 cap_net_raw,cap_sys_admin+eip

# 不使用 sudo 测试
rustnet --help
```

## GeoIP 数据库（可选）<a id="geoip-databases-optional"></a>

RustNet 支持 GeoIP 查询以显示远程 IP 的国家代码、城市名称和 ASN 信息。要启用此功能，请使用 MaxMind 的 `geoipupdate` 工具安装 [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) 数据库（需要免费的 [MaxMind 账户](https://www.maxmind.com/en/geolite2/signup)）。

**可用数据库：**

| 数据库 | 提供内容 | 标志 |
|---|---|---|
| `GeoLite2-Country.mmdb` | 国家代码和名称 | *（自动发现）* |
| `GeoLite2-ASN.mmdb` | ASN 编号和组织 | *（自动发现）* |
| `GeoLite2-City.mmdb` | 城市名称、邮政编码、**以及**国家 | *（自动发现）* |

> **提示：** `GeoLite2-City` 是 `GeoLite2-Country` 的超集。如果你安装了 City 数据库，就不需要再安装 Country 数据库。

### 配置要下载的数据库

在你的 `GeoIP.conf` 中，将 `EditionIDs` 设置为你想要的数据库：

```
# 仅 Country + ASN：
EditionIDs GeoLite2-Country GeoLite2-ASN

# City + ASN（City 已包含国家数据）：
EditionIDs GeoLite2-City GeoLite2-ASN

# 全部三个：
EditionIDs GeoLite2-Country GeoLite2-ASN GeoLite2-City
```

### macOS（Homebrew）

```bash
brew install geoipupdate
# 使用你的 MaxMind 账户凭据和 EditionIDs 编辑配置：
#   $(brew --prefix)/etc/GeoIP.conf
geoipupdate
```

数据库安装到 `$(brew --prefix)/share/GeoIP/`。

### Ubuntu/Debian

```bash
sudo apt-get install geoipupdate
# 使用你的 MaxMind 账户凭据和 EditionIDs 编辑 /etc/GeoIP.conf
sudo geoipupdate
```

数据库安装到 `/usr/share/GeoIP/`。

### Fedora/RHEL

```bash
sudo dnf install geoipupdate
# 使用你的 MaxMind 账户凭据和 EditionIDs 编辑 /etc/GeoIP.conf
sudo geoipupdate
```

数据库安装到 `/usr/share/GeoIP/`。

### Arch Linux

```bash
sudo pacman -S geoipupdate
# 使用你的 MaxMind 账户凭据和 EditionIDs 编辑 /etc/GeoIP.conf
sudo geoipupdate
```

数据库安装到 `/usr/share/GeoIP/`。

### FreeBSD

```bash
pkg install geoipupdate
# 使用你的 MaxMind 账户凭据和 EditionIDs 编辑 /usr/local/etc/GeoIP.conf
sudo geoipupdate
```

数据库安装到 `/usr/local/share/GeoIP/`。

### 手动指定

如果你的数据库在非标准位置，请直接指定：

```bash
# Country + ASN：
rustnet --geoip-country /path/to/GeoLite2-Country.mmdb --geoip-asn /path/to/GeoLite2-ASN.mmdb

# City + ASN（City 已包含国家数据）：
rustnet --geoip-city /path/to/GeoLite2-City.mmdb --geoip-asn /path/to/GeoLite2-ASN.mmdb
```

RustNet 从标准位置自动发现数据库。运行 `rustnet --help` 查看完整的搜索路径列表。

## 故障排查<a id="troubleshooting"></a>

### 常见安装问题<a id="common-installation-issues"></a>

#### 权限被拒绝错误<a id="permission-denied-errors"></a>

**在 macOS 上：**

- 确保你在 `access_bpf` 组中：`groups | grep access_bpf`
- 检查 BPF 设备权限：`ls -la /dev/bpf0`
- 尝试使用 sudo 运行以确认是权限问题
- 组变更后注销并重新登录

**在 Linux 上：**

- 检查 Linux capabilities 是否已设置：`getcap $(which rustnet)` 或 `getcap ~/.cargo/bin/rustnet`
- 验证 libpcap 是否已安装：`ldconfig -p | grep pcap`
- 尝试使用 sudo 运行以确认是权限问题：`sudo $(which rustnet)`

#### 未找到合适的捕获接口<a id="no-suitable-capture-interfaces-found"></a>

- 检查可用接口：`ip link show`（Linux）或 `ifconfig`（macOS）
- 尝试显式指定接口：`rustnet -i eth0`
- 确保接口已启动并拥有 IP 地址
- 某些虚拟接口可能不支持数据包捕获

#### 操作不被允许（已设置 Linux capabilities）<a id="operation-not-permitted-with-capabilities-set"></a>

- Linux capabilities 可能已被系统更新移除
- 重新应用 Linux capabilities（现代）：`sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' $(which rustnet)`
- 某些文件系统不支持扩展属性（Linux capabilities）
- 尝试将二进制文件复制到不同的文件系统（例如从 NFS 复制到本地磁盘）

#### 已设置 Linux capabilities 但 eBPF 不可用<a id="ebpf-unavailable-despite-capabilities-being-set"></a>

如果 RustNet 在运行 `setcap` 后仍显示 `Process Detection: procfs` 并伴随降级消息，请按以下步骤排查。TUI 在第二行状态栏显示实际原因 —— 用它跳转到下方正确的章节。

**1. `file caps ignored: binary on a nosuid mount`**

内核会静默忽略位于以 `nosuid` 选项挂载的文件系统上的二进制文件的 Linux capabilities。常见 culprit：`/home` 在加固发行版上、`/tmp`、可移动介质、容器内的某些 bind-mount。

```bash
# 查找持有该二进制文件的挂载点并检查其选项
findmnt -T $(realpath $(which rustnet)) -o TARGET,OPTIONS
# 如果 OPTIONS 列包含 "nosuid"，Linux capabilities 将不会生效。

# 修复：将二进制文件安装或复制到没有 nosuid 的挂载点
sudo install -m 0755 $(which rustnet) /usr/local/bin/rustnet
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/local/bin/rustnet
/usr/local/bin/rustnet
```

**2. `BPF denied (check perf_event_paranoid / AppArmor / unprivileged_bpf_disabled)`**

Linux capabilities 已授予，但内核返回了 `EPERM` 或 `EACCES`。三层可能阻止它 —— 按此顺序检查：

```bash
# 2a. perf_event_paranoid（Debian 上最常见的原因）。
#     Debian 13 默认 kernel.perf_event_paranoid=3，这会阻止
#     非 root 用户的 perf_event_open(2) —— 因此也阻止 kprobe attach ——
#     *即使有 CAP_PERFMON*。上游内核最高只到 2，
#     其中 CAP_PERFMON 正确绕过限制。
#
#     Ubuntu 使用了不同的补丁（paranoid=4），该补丁在
#     2025 年底更新以尊重 CAP_PERFMON，因此在较新的 Ubuntu 内核上
#     （Jammy 5.15.0-165+、Noble 6.8.0-91+、Plucky 6.14.0-37+、
#     Questing 6.17.0-14+、Resolute 6.18.0-8+）仅 `setcap` 就
#     足够了 —— 无需 sysctl 更改。Debian 的等效补丁
#     （bug #994044）从未更新，并在 2025 年被归档
#     且未修复，因此 Debian 用户仍需要下方的变通方法。
sysctl kernel.perf_event_paranoid
# 如果值为 3（Debian）或旧 Ubuntu 内核上的 4，将其降到 2：
sudo sysctl kernel.perf_event_paranoid=2
# 使其在重启后持久：
echo 'kernel.perf_event_paranoid = 2' | \
  sudo tee /etc/sysctl.d/99-rustnet.conf

# 2b. AppArmor 限制 rustnet（Debian/Ubuntu 默认安装 AppArmor）。
sudo aa-status | grep rustnet
# 如果已列出，要么禁用该配置文件，要么添加一条规则允许
# Linux capability `bpf`、Linux capability `perfmon`，以及该二进制文件的 bpf() 系统调用。

# 2c. unprivileged_bpf_disabled（Debian 设置为 =2；文件 Linux capabilities 应能绕过）。
sysctl kernel.unprivileged_bpf_disabled

# 确认 Linux capabilities 在 exec 时实际生效：
grep ^Cap /proc/$(pgrep -n rustnet)/status
# CapEff 必须包含 CAP_BPF（位 39）和 CAP_PERFMON（位 38）。
```

**3. `kprobe attach failed: <symbol>`**

内核缺少 eBPF 探针想要附加的符号。这通常是内核配置问题（例如 CONFIG_IPV6 禁用、CONFIG_KPROBES 关闭，或符号被内联）。RustNet 当前附加到
`tcp_connect`、`inet_csk_accept`、`udp_sendmsg`、`tcp_v6_connect`、
`udpv6_sendmsg`、`ping_v4_sendmsg` 和 `ping_v6_sendmsg`。

```bash
# 检查失败符号是否存在于运行中的内核中：
sudo grep '<symbol_name>' /proc/kallsyms
```

如果符号确实缺失，eBPF 进程检测将无法在此内核构建上工作；procfs 回退继续正常工作。

**4. `kernel BTF unavailable`**

CO-RE 重定位需要 `/sys/kernel/btf/vmlinux`。在精简内核上（某些嵌入式 / 最小云镜像）该文件不存在。

```bash
ls /sys/kernel/btf/vmlinux
# 如果缺失：安装与你的运行内核匹配的 kernel-debuginfo / linux-image 包，
# 或使用 CONFIG_DEBUG_INFO_BTF=y 重新构建内核。
```

**5. 在 Docker / Podman 中**

即使有文件 Linux capabilities，容器内的*bounding*集合也必须包含 `CAP_BPF` 和 `CAP_PERFMON`，否则它们在 exec 时会被屏蔽：

```bash
docker run --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON \
           --net=host --pid=host rustnet
# 可选，如果你的容器的 seccomp 配置文件阻止 bpf(2)：
#   --security-opt seccomp=unconfined
# 或如果 AppArmor 监管 BPF：
#   --security-opt apparmor=unconfined
```

**6. `eBPF load failed: ...`**

兜底分支携带原始 libbpf 错误文本。使用
`RUST_LOG=debug rustnet 2>&1 | tee rustnet.log` 重新运行并检查完整
链 —— 它通常包含一个 `errno` 名称（`EPERM`、`EACCES`、`ENOSPC`
表示 memlock 等），指向根本原因。

#### Windows：未找到 Npcap<a id="windows-npcap-not-found"></a>

- 确保从 https://npcap.com/dist/ 安装了 Npcap
- 在 Npcap 安装期间，选择 **"WinPcap API compatible mode"**
- 验证 Npcap 服务正在运行：`sc query npcap`
- 尝试使用管理员权限重新安装 Npcap

#### 构建错误<a id="build-errors"></a>

**Windows - 未找到 Npcap SDK：**
- 确保 `LIB` 环境变量包含 Npcap SDK 路径
- 检查 SDK 是否解压到没有空格的目录
- 为你的 Rust 工具链使用正确的架构（x64 与 x86）

**Linux 构建失败：**
```bash
# 安装所有必需的依赖
# Debian/Ubuntu
sudo apt-get install build-essential pkg-config libpcap-dev libelf-dev zlib1g-dev clang llvm

# RedHat/CentOS/Fedora
sudo yum install make pkgconfig libpcap-devel elfutils-libelf-devel zlib-devel clang llvm
```

#### Windows：图表在 PowerShell 中显示不正确<a id="windows-graphs-display-incorrectly-in-powershell"></a>

如果图表和 sparkline 在 PowerShell 中显示损坏（显示问号或乱码字符），这是**字体问题**，不是 RustNet 的 bug。默认的控制台字体（Consolas、Lucida Console）缺少图表渲染使用的 Unicode Braille 字符支持。

**解决方案：** 安装支持 Unicode Braille 的字体：

1. 下载并安装 [Iosevka](https://typeof.net/Iosevka/) 或任意 [Nerd Font](https://www.nerdfonts.com/)
2. 打开 PowerShell 属性（右键标题栏 → 属性）
3. 在字体选项卡中选择已安装的字体
4. 重启 PowerShell

**替代方案：** 使用 [Windows Terminal](https://aka.ms/terminal)，它开箱即用地提供更好的 Unicode 支持。

参见：[ratatui#457](https://github.com/ratatui/ratatui/issues/457)、[gtop#21](https://github.com/aksakalli/gtop/issues/21)

### 获取帮助<a id="getting-help"></a>

如果你遇到此处未涵盖的问题：

1. 启用调试日志：`rustnet --log-level debug`
2. 检查 `logs/` 目录中的日志文件
3. 在 [GitHub](https://github.com/domcyrus/rustnet/issues) 上开 issue，并提供：
   - 你的操作系统和版本
   - 使用的安装方法
   - 日志中的错误消息
   - 权限验证命令的输出

### 安全最佳实践<a id="security-best-practices"></a>

1. **尽可能使用 Linux capabilities，而不是 sudo**（Linux）
2. **使用基于组的访问而非以 root 运行**（macOS）
3. **定期审计**哪些用户拥有数据包捕获特权
4. **考虑网络分段**如果在生产系统上运行
5. **监控日志文件**以发现未授权的使用
6. **在不再需要 RustNet 时移除相关的 Linux capabilities**：

   ```bash
   # Linux：移除 Linux capabilities
   sudo setcap -r /path/to/rustnet

   # macOS：从组中移除
   sudo dseditgroup -o edit -d $USER -t user access_bpf
   ```

### 与系统监控集成<a id="integration-with-system-monitoring"></a>

对于生产环境，请考虑：

- 数据包捕获访问的**审计日志**
- **网络监控策略**和合规要求
- 特权网络访问的**用户访问审查**
- 配置管理系统中的**自动化 Linux capabilities 管理**

此权限配置确保 RustNet 能够在捕获数据包的同时遵循安全最佳实践和最小权限原则。
