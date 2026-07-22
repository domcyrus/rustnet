<p align="center">
  <h1 align="center">RustNet</h1>
  <p align="center">
    <strong>プロセス単位で TCP、UDP、QUIC 接続を監視できる、サンドボックス対応のターミナルネットワークモニター。</strong>
  </p>
</p>

<p align="center">
  <a href="README.md">English</a> | <a href="README.zh-CN.md">简体中文</a> | <strong>日本語</strong>
</p>

<p align="center">
  <img src="./assets/rustnet.gif" alt="RustNet demo" width="800">
</p>

RustNet は、各接続を所有するプロセス、通信量、状態、アプリケーションプロトコルをリアルタイムで表示します。Linux、macOS、Windows、FreeBSD に対応しています。

## 主な機能

- TCP、UDP、QUIC 接続とプロセスの対応付け
- HTTP、TLS/SNI、DNS、SSH、QUIC などの深層パケット解析
- 再送、順序入れ替わり、帯域幅、接続状態のリアルタイム表示
- `port:`、`process:`、`sni:`、`state:` などのフィルター
- 注釈付き PCAPNG、PCAP と JSONL sidecar、JSON ログの出力
- ローカル GeoIP データベースによる国、ASN、都市情報
- Linux Landlock、macOS Seatbelt、Windows の権限削減によるサンドボックス
- オプションの Kubernetes pod、namespace、container 帰属情報

## インストール

macOS または Linux:

```bash
brew install rustnet
```

Ubuntu 25.10 以降:

```bash
sudo add-apt-repository ppa:domcyrus/rustnet
sudo apt update && sudo apt install rustnet
```

Fedora 42 以降:

```bash
sudo dnf copr enable domcyrus/rustnet
sudo dnf install rustnet
```

Arch Linux:

```bash
sudo pacman -S rustnet
```

Cargo:

```bash
cargo install rustnet-monitor
```

Windows では Npcap を WinPcap API 互換モードでインストールし、管理者 PowerShell で実行します。

```powershell
choco install rustnet
```

Docker、FreeBSD、ソースビルド、その他の方法は [INSTALL.md](INSTALL.md) を参照してください。

## 実行

パケットキャプチャには通常、昇格された権限が必要です。

```bash
sudo rustnet
```

Linux 5.8 以降では必要な capabilities を付与すると、sudo なしで実行できます。

```bash
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which rustnet)"
rustnet
```

よく使うオプション:

```bash
rustnet -i eth0                         # インターフェースを指定
rustnet -i any                          # Linux ですべてのインターフェースを監視
rustnet --show-localhost                # localhost 接続を表示
rustnet --no-resolve-dns                # 逆引き DNS を無効化
rustnet --no-dpi                        # 深層パケット解析を無効化
rustnet --pcapng-export capture.pcapng  # 注釈付き PCAPNG を出力
```

## 基本操作

| キー | 操作 |
|---|---|
| `q` | 終了。確認のため 2 回押す |
| `Tab` / `Shift+Tab` | 次または前のタブ |
| `1` から `5` | Overview、Details、Activity、Graph、Help |
| `↑/k` `↓/j` | 選択を移動 |
| `Enter` | 接続の詳細を表示 |
| `/` | フィルター入力 |
| `s` / `S` | 並び替え列または方向を変更 |
| `a` | プロセス単位のグループ表示 |
| `t` | 終了済み接続の表示を切り替え |
| `r` | 表示、並び替え、フィルターをリセット |

フィルター例:

```text
/process:firefox
/dport:443 sni:github.com
/state:established proto:tcp
```

すべてのオプション、キー操作、フィルター、ログ、PCAP 出力については [USAGE.md](USAGE.md) を参照してください。

## セキュリティ

RustNet は非プロミスキャスな読み取り専用キャプチャを行い、パケット、ルーティング、ファイアウォールを変更しません。初期化後に不要な権限を削除し、対応 OS ではサンドボックスを有効にします。詳細は [SECURITY.md](SECURITY.md) を参照してください。

## 関連ドキュメント

- [INSTALL.md](INSTALL.md): 詳細なインストール、権限設定、トラブルシューティング
- [USAGE.md](USAGE.md): 詳細な使用方法
- [ARCHITECTURE.md](ARCHITECTURE.md): 設計とプラットフォーム別実装
- [CONTRIBUTING.md](CONTRIBUTING.md): コントリビューションガイド

## ライセンス

Apache License 2.0。詳細は [LICENSE](LICENSE) を参照してください。
