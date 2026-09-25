# Icon artwork

## English

Edit [the SVG master](../../assets/rustnet.svg), then regenerate all exports
with [generate-icons.py](../../scripts/generate-icons.py). The cyan
`#0891B2` and green `#10B981` come from the default theme's accent and RX
reference colors. The terminal can display different shades through its ANSI
palette; the artwork uses fixed RGB colors.

Run from the repository root with Python 3.10+. The only export dependency is
`resvg-py`, a Python binding to the Rust SVG renderer. It is not needed to build
or release RustNet. Install it in a temporary environment (macOS/Linux):

```sh
icon_tools="$(mktemp -d)"
python3 -m venv "$icon_tools"
"$icon_tools/bin/python" -m pip install resvg-py==0.5.0
"$icon_tools/bin/python" scripts/generate-icons.py
```

Commit the regenerated files together. Review the transparent logo on light
and dark backgrounds, and the desktop icon at 16, 24, 32, 48, 64 and 256 pixels.
Rendering can differ across renderer versions; use the pinned version.

- Linux: 256px PNG plus scalable SVG, installed by DEB, RPM, PPA, COPR and OBS.
- macOS: 1024px PNG, ICNS with standard/Retina sizes, and a 900x450 DMG
  background matching the positions in `.github/workflows/release.yml`.
- Windows: ICO with 16/24/32/48/64/128/256px images, used by the MSI shortcut
  and Installed Apps entry. The CLI executable does not embed an icon.
- README: the English, Chinese and Japanese headers use the hosted master
  SVG so packaged READMEs do not require a local image. The new logo appears
  there once the master is merged into `main`; viewing it requires network access.
- Chocolatey: keep the Linux PNG path stable, because `rustnet.nuspec` in
  `domcyrus/rustnet-chocolatey` already links to it. No separate asset copy.
- FreeBSD: `domcyrus/rustnet-bsd` copies the main repository's `assets/`
  into its archive. Homebrew and AUR binary packages do not install launchers.

## 简体中文

修改 [SVG 源文件](../../assets/rustnet.svg)，然后在仓库根目录运行上述命令，
使用 [generate-icons.py](../../scripts/generate-icons.py) 重新生成全部图标。
青色 `#0891B2` 和绿色 `#10B981` 分别来自默认主题的强调色和接收流量参考色。
终端的 ANSI 配色可能不同；图标使用固定的 RGB 值。

需要 Python 3.10+ 和固定版本的 `resvg-py`（Rust SVG 渲染器的 Python 绑定）。
此依赖仅用于导出图标，不影响 Rust 构建或发布。将生成的文件一起提交，
并检查浅色、深色背景及小尺寸显示。

- Linux：256 像素 PNG 和可缩放 SVG，由 DEB、RPM、PPA、COPR 和 OBS 安装。
- macOS：1024 像素 PNG、包含标准及 Retina 尺寸的 ICNS，以及与发布流程图标位置
  对应的 900×450 DMG 背景。
- Windows：ICO 包含 16/24/32/48/64/128/256 像素尺寸，用于 MSI 快捷方式和
  已安装应用列表；命令行程序本身不嵌入图标。
- 三种语言的 README 使用托管 SVG，避免依赖本地图像；源文件合并到 `main`
  后显示新图标，查看时需要网络连接。
- Chocolatey 已引用主仓库的 Linux PNG，须保持路径不变，无需复制资源。
- FreeBSD 构建会复制主仓库的 `assets/`；Homebrew 和 AUR 二进制包不安装桌面启动器。

## 日本語

[SVG 原本](../../assets/rustnet.svg) を編集し、リポジトリのルートで上記のコマンドを
実行して [generate-icons.py](../../scripts/generate-icons.py) で全形式を再生成します。
シアン `#0891B2` と緑 `#10B981` は、標準テーマのアクセント色と受信トラフィックの
参照色です。端末の ANSI パレットとは異なり、画像では固定 RGB 値を使います。

Python 3.10+ と指定バージョンの `resvg-py`（Rust SVG レンダラーの Python バインディング）
が必要です。この依存は画像の書き出し専用で、Rust のビルドやリリースには不要です。
生成物をまとめてコミットし、明暗の背景と小さいサイズで表示を確認してください。

- Linux：256px PNG と SVG を DEB、RPM、PPA、COPR、OBS に同梱します。
- macOS：1024px PNG、標準・Retina サイズを含む ICNS、リリース処理のアイコン配置に
  合わせた 900×450 の DMG 背景を生成します。
- Windows：ICO は 16/24/32/48/64/128/256px を含み、MSI のショートカットと
  インストール済みアプリ一覧で使います。CLI 実行ファイルには埋め込みません。
- 3 言語の README は公開 SVG を参照するため、ローカル画像は不要です。
  `main` へのマージ後に新しいロゴが表示され、閲覧にはネットワーク接続が必要です。
- Chocolatey は既に主リポジトリの Linux PNG を参照しており、パスを維持すれば
  別の画像コピーは不要です。
- FreeBSD は主リポジトリの `assets/` を同梱します。Homebrew と AUR の
  バイナリパッケージはデスクトップランチャーをインストールしません。
