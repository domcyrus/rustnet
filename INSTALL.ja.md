<p align="center"><a href="INSTALL.md#debianubuntu-deb-packages">English</a> | <a href="INSTALL.zh-CN.md#debianubuntu-deb-packages">简体中文</a> | <strong>日本語</strong></p>

# Debian/Ubuntu での DEB パッケージのインストール

GitHub Releases で配布される DEB のパッケージ名は `rustnet-monitor`、起動コマンドは `rustnet` です。Ubuntu PPA のバイナリパッケージ名は `rustnet` です。

v1.7.0 の GNU バイナリには glibc 2.35 以降が必要です。ARM64 版は Ubuntu 22.04 以降および Debian 12/13 に、ARMv7 版は Debian 12/13 に対応しています。ARMv7 版には libpcap が組み込まれています。これらの互換性修正は v1.6.0 の配布物には適用されません。

[GitHub Releases](https://github.com/domcyrus/rustnet/releases) からシステムのアーキテクチャ（`amd64`、`arm64`、`armhf`）に合う DEB をダウンロードします。ダウンロード先のディレクトリで次のコマンドを実行し、インストールしたパッケージと実行ファイルの権限を確認します。

```bash
sudo apt install "./Rustnet_LinuxDEB_$(dpkg --print-architecture).deb"
dpkg-query -W rustnet-monitor
getcap /usr/bin/rustnet
```

**v1.7.0** の配布用 DEB には権限設定用のスクリプトが含まれていません。`getcap` や `setcap` が見つからない場合は `libcap2-bin` をインストールしてください。`getcap` の出力に `cap_net_raw` がない場合は、次の手順でキャプチャ権限を付与します。

```bash
sudo apt install libcap2-bin
sudo setcap 'cap_net_raw+eip' /usr/bin/rustnet
getcap /usr/bin/rustnet
```

`cap_net_raw` が有効（`e` フラグ付き）であることを確認したら、一般ユーザーで `rustnet` を起動できます。アップグレード後は権限を再確認してください。eBPF によるプロセス検出も使う場合は、[権限設定（英語）](INSTALL.md#permissions-setup)を参照してください。

**未リリースの DEB（GitHub 配布版と PPA 版）** は、初回の対話型インストール時に、ローカルユーザーが sudo なしでキャプチャできるようにするかを尋ねます。**Yes（はい）** を選ぶと `/usr/bin/rustnet` に `CAP_NET_RAW` が付与され、このプログラムを実行できるすべてのユーザーがキャプチャできます。共有マシンや権限を制限したサービスでは、**No（いいえ）** を選ぶと実行ファイルに権限を付与せずに使用できます。

選択を変更するには `sudo dpkg-reconfigure rustnet-monitor`（PPA 版は `sudo dpkg-reconfigure rustnet`）を実行します。無人インストールの既定値は **No** です。アップグレード時は再度質問せず、保存した選択を引き継ぎます。v1.7.0 で手動で権限を付与していた場合は、アップグレード後に上記のコマンドを一度実行してキャプチャを有効にしてください。

無人インストールでキャプチャを有効にするには、DEB をインストールする**前に**回答を設定します。

```bash
echo 'rustnet-monitor rustnet/allow-capture boolean true' | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get install "./Rustnet_LinuxDEB_$(dpkg --print-architecture).deb"
getcap /usr/bin/rustnet
```

PPA 版では最初のフィールドを `rustnet` に変更し、`rustnet` パッケージをインストールしてください。eBPF によるプロセス検出も使う場合は、同じパッケージ名で `rustnet/enable-ebpf boolean true` も事前に設定します。キャプチャを有効にすると `CAP_BPF` と `CAP_PERFMON` も付与されます。設定時に必要な権限が利用できない場合、実行ファイルには権限が付与されません。
