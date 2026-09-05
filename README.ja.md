<p align="center">
  <h1 align="center">RustNet</h1>
  <p align="center">
    <strong>プロセス単位で TCP、UDP、QUIC 接続を監視できる、ターミナルと自動化に対応したサンドボックス対応ネットワークモニター。</strong>
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

- TCP、UDP、QUIC 接続とプロセスの対応付け。詳細には PID、実行ファイル、ユーザー/グループ名、照合の信頼度、全プラットフォーム共通の親プロセスチェーン（上限あり）を表示
- Linux 5.11 以降では、起動時の BPF task-file イテレーターにより、ファイル capabilities で実行した場合でも root や他ユーザーが所有する既存 socket を識別
- HTTP、TLS/SNI、DNS、SSH、QUIC、WireGuard、OpenVPN などの深層パケット解析
- TCP、QUIC ハンドシェイク、DNS 応答、ICMP エコーの往復時間（RTT）と、TCP の再送・順序入れ替わりをリアルタイム表示。Overview テーブルではプロトコル別のヘルスバッジにより、TCP の問題、明示的な QUIC Retry/バージョンネゴシエーション、トランザクション型 UDP の再試行/タイムアウトを表示し、重大度順に並べ替え可能
- Host タブに TCP LISTEN ソケット、UDP BOUND エンドポイント、TCP 状態集計、観測 RTT、所有プロセス、インターフェース統計を表示
- `port:`、`process:`、`sni:`、`state:` などのフィルター
- TUI を使わず、バージョン付き JSONL スナップショットをストリーミング出力、または終了時に最終 JSON スナップショットを 1 件出力できるヘッドレスモード。対話表示と同じ接続フィルターを利用可能
- 注釈付き PCAPNG、PCAP と JSONL sidecar、JSON ログの出力
- ローカル GeoIP データベースによる国、ASN、都市情報
- ARP トラフィックから受動的に学習した LAN 機器・ゲートウェイの MAC アドレスとベンダー表示（内蔵 IEEE OUI データベース）
- Linux Landlock、macOS Seatbelt、Windows の権限削減によるサンドボックス
- オプションの Kubernetes pod、namespace、container 帰属情報

パケットの解析は並列に行い、接続情報と注釈付きエクスポートの更新はキャプチャ順を維持します。
処理キューの上限は 10,000 パケットです。これはアプリのその他のメモリ使用量を含まず、トラフィックの急増や継続的な過負荷によってパケットを破棄する場合があります。

## インストール

macOS または Linux:

```bash
brew install rustnet
```

Ubuntu 22.04 LTS 以降 / Linux Mint 21 以降 / Pop!_OS 22.04 以降:

```bash
sudo add-apt-repository ppa:domcyrus/rustnet
# Pop!_OS の場合: sudo apt-manage add ppa:domcyrus/rustnet
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

Windows では Npcap を標準設定でインストールできます。WinPcap API 互換モードは不要です。Npcap の設定によっては管理者 PowerShell が必要です。

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
rustnet --theme tokyo-night             # カラーテーマ（muted［既定］、vivid、catppuccin-mocha、tokyo-night、gruvbox、nord）
rustnet --pcapng-export capture.pcapng  # 注釈付き PCAPNG を出力
```

既定では TUI が起動します。スクリプトやサービスではヘッドレスモードを使用できます。

```bash
rustnet --headless                                      # JSONL スナップショットをストリーミング出力
rustnet --headless --duration 30 --output json         # 最終スナップショットを 1 件出力
rustnet --headless --filter 'process:curl app:https'   # 接続フィルターを適用
```

ヘッドレスモードの既定は `--output jsonl` で、設定された更新間隔ごとにバージョン付きスナップショットを出力します。`--output json` は監視終了時にバージョン付きの最終スナップショットを 1 件出力します。`--duration` は指定した秒数後にキャプチャを停止し、`--filter` は TUI と同じ構文を受け付けます。ヘッドレスモードでは stdout に機械可読の出力だけを書き込みます。キャプチャの起動に失敗した場合は、ゼロ以外の終了ステータスを返します。

スナップショットの接続 ID は履歴への移行後も変わらず、同じエンドポイントを再利用する別の接続を区別します。転送速度のフィールド名は `outgoing_bytes_per_second` と `incoming_bytes_per_second` で、単位はバイト毎秒です。終了処理がタイムアウトした場合は、状態を `stopping` とし、未完了のワーカー数を報告してゼロ以外のステータスで終了します。

JSONL は状態のスナップショットであり、完全なパケットログや接続イベント履歴ではありません。短時間の接続や、同じエンドポイントを再利用する接続は、ドロップ数がゼロで `runtime.snapshot_generation` が連続していても、全出力を通して一度も現れない場合があります。全体の `stats.packets_processed` が正しくても、表示された接続のカウンター合計とは一致しません。累積カウンターをスナップショット間で合算したり、最終スナップショットを完全な履歴と見なしたりしないでください。

パケット単位の分析には、スナップショットと別に PCAP を保存します。

```bash
umask 077
rustnet --headless --interface eth0 --duration 60 --refresh-interval 5000 \
  --pcap-export capture.pcap > snapshots.jsonl
```

書き出しが成功した場合、PCAP はキャプチャフィルターとキャプチャ長の範囲内で、バックエンドが受信したパケットを保存します。キャプチャ前に失われたパケットは復元できません。`stats.packets_dropped`（処理キュー）、`stats.capture_packets_dropped`（キャプチャ）、`stats.interface_packets_dropped`（対応環境のインターフェース）を確認してください。さらに `stats.pcap_export_errors` がゼロであることと終了処理の結果を確認し、`stats.pcap_records_written` と実際のファイルを照合します。ドロップがなくても書き込みやフラッシュの失敗でファイルが不完全になる場合があります。これらは異なる段階の指標であり、完全性の無条件な証明ではありません。完全性を検証する場合は同じインターフェースとキャプチャフィルターで独立に取得した PCAP と照合し、そのドロップ数も確認したうえで、総数だけでなくパケットの識別情報と長さを比較します。`--filter` はスナップショットの行を、`--bpf-filter` はキャプチャ対象の通信を絞ります。`--json-log` は別の接続イベント出力で、パケットキャプチャではありません。

出力される各レコードは選択された接続の完全なスナップショットです。接続数、メタデータ量、更新頻度が増えると CPU、メモリ、ディスクの負荷も増えます。5 秒間隔は出力頻度を下げますが、途中の接続を保存する保証はなく、バックグラウンド収集の負荷もなくなりません。無人運用の前に実際の負荷と保存容量を測定してください。

リダイレクトした stdout、JSON ログ、PCAP とそのサイドカー、PCAPNG には異なるファイルを指定してください。RustNet は設定された出力を切り詰める前に重複を拒否しますが、シェルの `>` はプログラムの起動前にファイルを切り詰める場合があります。

テーマと各色の上書きは `~/.config/rustnet/config.toml` でも設定できます（`--theme` が優先）。詳細は [USAGE.md](USAGE.md#--theme-preset) を参照してください。

## 基本操作

| キー | 操作 |
|---|---|
| `q` | 終了。確認のため 2 回押す |
| `Tab` / `Shift+Tab` | 次または前のタブ |
| `1` から `5` | Overview、Details、Activity、Graph、Host |
| `↑/k` `↓/j` | 選択を移動 |
| `Enter` | 接続の詳細を表示 |
| `/` | フィルター入力 |
| `s` / `S` | 並び替え列または方向を変更 |
| `a` | プロセス単位のグループ表示 |
| `Space` | 選択したプロセスグループを展開または折りたたむ |
| `t` | 終了済み接続の表示を切り替え |
| `i` | Overview では System 情報を切り替え、Host ではインターフェース表示に切り替える |
| `r` | 表示、並び替え、フィルターをリセット |
| `h` | 現在のタブに対応したヘルプオーバーレイを表示または閉じる |

Overview の下部ステータスバーでは、プロセスグループ表示と履歴接続の
有効状態がハイライトされます。グループ表示中は、選択したグループに
応じて `space expand` または `space collapse` も表示されます。

フィルター例:

```text
/process:firefox
/dport:443 sni:github.com
/state:established proto:tcp
```

すべてのオプション、キー操作、フィルター、ログ、PCAP 出力については [USAGE.md](USAGE.md) を参照してください。

## セキュリティ

RustNet は非プロミスキャスな読み取り専用キャプチャを行い、パケット、ルーティング、ファイアウォールを変更しません。初期化後に不要な権限を削除し、対応 OS ではサンドボックスを有効にします。詳細は [SECURITY.md](SECURITY.md) を参照してください。

Linux、macOS、FreeBSD では、要求された UID/GID の権限削減に失敗すると、ベストエフォートモードでもパケット処理スレッドの起動前に終了します。未対応の任意サンドボックス機能は引き続き省略できます。`--no-uid-drop` または `--no-sandbox` で明示的に無効化した場合は UID/GID の変更を行いません。

## 関連ドキュメント

- [INSTALL.md](INSTALL.md): 詳細なインストール、権限設定、トラブルシューティング
- [USAGE.md](USAGE.md): 詳細な使用方法
- [ARCHITECTURE.md](ARCHITECTURE.md): 設計とプラットフォーム別実装
- [CONTRIBUTING.md](CONTRIBUTING.md): コントリビューションガイド

## ライセンス

Apache License 2.0。詳細は [LICENSE](LICENSE) を参照してください。
