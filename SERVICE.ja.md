<p align="center"><a href="SERVICE.md">English</a> | <a href="SERVICE.zh-CN.md">简体中文</a> | <strong>日本語</strong></p>

# ヘッドレスサービスガイド

RustNet は Linux、macOS、Windows、FreeBSD のネイティブなサービスマネージャー、
または Docker Compose で継続的に実行できます。RustNet や付属のサービス定義を
インストールしても、監視は有効化も開始もされません。コマンドとデータ保持方針を
確認してから、明示的にサービスを有効化してください。

オプションなしの `rustnet` は常に対話型 TUI を起動します。このリポジトリの各
サービス定義は `--headless` を明示的に渡し、長期実行時の CPU とストレージ使用量を
抑えるため更新間隔を 5000 ms に設定します。CLI の既定値は引き続き 500 ms です。

## セキュリティ、出力、保持

ほとんどのシステムではパケットキャプチャに昇格権限が必要です。systemd、launchd、
rc.d の定義は root で起動し、RustNet がキャプチャを初期化した後、通常どおり
サンドボックスと権限縮小を適用します。Windows サービスは LocalSystem で動作し、
Npcap に依存します。Docker は `NET_RAW` だけを追加し、その他の Linux capability を
すべて削除してホストネットワークを使用します。

接続スナップショットには、プロセス名、アドレス、ホスト名、トラフィックメタデータが
含まれる場合があります。親ディレクトリを非公開にし、この情報を参照すべき運用者だけに
アクセスを許可してください。

サービスの既定値は次のとおりです。

| プラットフォーム | スナップショット出力 | 診断 | 付属の保持設定 |
|---|---|---|---|
| Linux systemd | `/var/lib/rustnet/headless.jsonl` | systemd journal | 日次ローテーション、7 ファイル、圧縮 |
| macOS launchd | `/var/db/rustnet/headless.jsonl` | `/var/db/rustnet/headless.err.log` | なし |
| Windows SCM | `%ProgramData%\Rustnet\rustnet.jsonl` | SCM でサービス状態を確認 | なし |
| FreeBSD rc.d | `/var/db/rustnet/headless.jsonl` | `/var/db/rustnet/headless.err.log` | なし |
| Docker Compose | コンテナの stdout | コンテナの stderr | Docker `json-file`、10 MB × 7 ファイル |

Linux では `copytruncate` を使うため、ローテーション中も RustNet は出力ディスクリプタを
保持できます。macOS、Windows、FreeBSD で長期運用する前にローカルのローテーションを
設定してください。使用中の出力ファイルを移動または置換する前にはサービスを停止します。
サービス定義を削除してもキャプチャ済みデータは削除されません。不要になった保持ファイル
だけを別途削除してください。

独自のヘッドレスコマンドでは、`--output-file FILE` により stdout の代わりに安全に
開いた通常ファイルへスナップショットを直接書き込めます。`--output jsonl` では新しい
実行がファイルへ追記されます。`--output json` では新しい実行が 1 件の最終スナップショット
でファイルを置換します。`--output-file`、`--output`、`--duration`、`--filter` はすべて
`--headless` が必要です。

```bash
# バージョン付きスナップショットストリームを追記
sudo rustnet --headless --output jsonl --output-file /var/lib/rustnet/custom.jsonl

# 60 秒後に 1 件の最終スナップショットでファイルを置換
sudo rustnet --headless --duration 60 --output json --output-file /var/lib/rustnet/final.json
```

## Linux の systemd

unit は RustNet が `/usr/bin/rustnet` にあることを前提とします。ディストリビューション
パッケージでは付属ファイルが自動配置される場合があります。このソースツリーから手動で
インストールする場合は次のようにします。

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

バイナリリリースアーカイブでは、展開したディレクトリから実行し、
`target/release/rustnet` を `./rustnet` に置き換えてください。

これらのコマンドは非アクティブな unit をインストールするだけです。任意のフィルターや
追加引数は `/etc/default/rustnet-headless` で設定します。このファイルから固定の
`--headless`、`--interface any`、`--refresh-interval 5000`、`--output jsonl` を
削除することはできません。

```bash
# ブート時に有効化し、今すぐ開始
sudo systemctl enable rustnet-headless.service
sudo systemctl start rustnet-headless.service

# 状態、診断、スナップショットを確認
systemctl status rustnet-headless.service
sudo journalctl -u rustnet-headless.service -f
sudo tail -F /var/lib/rustnet/headless.jsonl

# 停止して無効化
sudo systemctl stop rustnet-headless.service
sudo systemctl disable rustnet-headless.service
```

手動インストールした定義を削除する場合は、先に停止して無効化し、配置した定義ファイル
だけを削除します。

```bash
sudo rm /etc/systemd/system/rustnet-headless.service
sudo rm /etc/default/rustnet-headless
sudo rm /etc/logrotate.d/rustnet-headless
sudo systemctl daemon-reload
```

非公開の `/var/lib/rustnet` 状態ディレクトリとスナップショットは残ります。パッケージから
配置されたファイルには、そのパッケージマネージャーを使用してください。

## macOS の launchd

launchd の property list はリリースアプリが `/Applications/Rustnet.app` にあることを
前提とし、`/Applications/Rustnet.app/Contents/MacOS/rustnet` を実行します。app bundle を
その場所へ配置してから、付属インストーラーを実行します。

```bash
sudo /Applications/Rustnet.app/Contents/Resources/service/launchd/install-rustnet-headless.sh
```

CLI またはバイナリアーカイブ版では、`rustnet` を安定した絶対パスにインストールし、
そのパスを `resources/packaging/macos/launchd` 内のスクリプトへ明示的に渡します。

```bash
sudo install -m 0755 rustnet /usr/local/bin/rustnet
sudo env RUSTNET_BIN=/usr/local/bin/rustnet \
  resources/packaging/macos/launchd/install-rustnet-headless.sh
```

インストーラーはモード `0700` で `/var/db/rustnet` を作成し、
`com.domcyrus.rustnet-headless.plist` を配置してジョブを無効化します。bootstrap や起動は
行いません。準備ができてから有効化してロードしてください。property list に
`RunAtLoad` があるため、bootstrap によって監視も開始されます。

```bash
# 有効化して開始
sudo launchctl enable system/com.domcyrus.rustnet-headless
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/com.domcyrus.rustnet-headless.plist

# 状態、診断、スナップショットを確認
sudo launchctl print system/com.domcyrus.rustnet-headless
sudo tail -F /var/db/rustnet/headless.err.log
sudo tail -F /var/db/rustnet/headless.jsonl

# ロード済みジョブを再起動
sudo launchctl kickstart -k system/com.domcyrus.rustnet-headless

# 停止、アンロード、無効化
sudo launchctl bootout system/com.domcyrus.rustnet-headless
sudo launchctl disable system/com.domcyrus.rustnet-headless
```

bootout の後で定義をアンインストールします。

```bash
sudo rm /Library/LaunchDaemons/com.domcyrus.rustnet-headless.plist
```

app bundle と `/var/db/rustnet` のデータは、別途削除するまで残ります。

## Windows の Service Control Manager

最初に標準オプションで Npcap をインストールし、管理者 PowerShell から RustNet MSI を
インストールします。

```powershell
msiexec.exe /i .\rustnet-<version>.msi
```

MSI は `Rustnet` サービスを手動スタートとして登録します。サービスの起動や自動スタートの
設定は行いません。コマンドには `--windows-service --headless --output jsonl
--output-file "%ProgramData%\Rustnet\rustnet.jsonl" --refresh-interval 5000` が含まれます。
内部オプション `--windows-service` は SCM による起動専用です。TUI には引き続き通常の
`rustnet` を使用してください。

```powershell
# 必要に応じて自動スタートを有効化し、今すぐ開始
Set-Service -Name Rustnet -StartupType Automatic
Start-Service -Name Rustnet

# 状態を確認し、スナップショットを追跡
Get-Service -Name Rustnet
sc.exe queryex Rustnet
Get-Content "$env:ProgramData\Rustnet\rustnet.jsonl" -Wait

# System イベントログで SCM のライフサイクルエラーを確認
Get-WinEvent -LogName System |
  Where-Object ProviderName -eq 'Service Control Manager' |
  Where-Object Message -Match 'Rustnet' |
  Select-Object -First 20

# 停止して無効化
Stop-Service -Name Rustnet
Set-Service -Name Rustnet -StartupType Disabled
```

Windows の設定画面からアンインストールするか、管理者 PowerShell で同じ MSI を使います。

```powershell
msiexec.exe /x .\rustnet-<version>.msi
```

インストーラーはサービスを停止して削除します。`%ProgramData%\Rustnet` の保持ファイルは
残る場合があるため、必要に応じて別途削除してください。

## FreeBSD の rc.d

rc.d スクリプトは RustNet が `/usr/local/bin/rustnet` にあることを前提とします。
バイナリを配置してから、付属の定義インストーラーを実行します。

```sh
sudo install -m 0555 target/release/rustnet /usr/local/bin/rustnet
sudo resources/packaging/freebsd/rc.d/install-rustnet-headless.sh
```

バイナリリリースアーカイブでは、`target/release/rustnet` を `./rustnet` に
置き換えてください。

インストーラーはモード `0700` で `/var/db/rustnet` を作成し、`rustnet_headless` を配置して
`rustnet_headless_enable=NO` を維持します。

```sh
# ブート時に有効化し、今すぐ開始
sudo sysrc rustnet_headless_enable=YES
sudo service rustnet_headless start

# 状態、診断、スナップショットを確認
sudo service rustnet_headless status
sudo tail -F /var/db/rustnet/headless.err.log
sudo tail -F /var/db/rustnet/headless.jsonl

# 停止して無効化
sudo service rustnet_headless stop
sudo sysrc rustnet_headless_enable=NO
```

追加の CLI 引数は `/etc/rc.conf` の `rustnet_headless_extra_args` で設定できます。スクリプトは
明示的な `--headless --refresh-interval 5000 --output jsonl` を常に維持します。

手動インストールした定義を削除します。

```sh
sudo rm /usr/local/etc/rc.d/rustnet_headless
sudo sysrc -x rustnet_headless_enable
sudo sysrc -x rustnet_headless_extra_args
```

バイナリと `/var/db/rustnet` のデータは、別途削除するまで残ります。

## Docker Compose

付属の Compose ファイルは既存のイメージをビルドし、そのコマンドを明示的なヘッドレス
引数で上書きします。イメージのビルドや pull だけでは監視は開始されません。

```bash
# 起動せずにビルド
docker compose -f compose.headless.yml build

# 明示的に開始
docker compose -f compose.headless.yml up -d

# バイナリリリースアーカイブでは、VERSION を先頭の v なしのバージョンに置換
RUSTNET_IMAGE_TAG=VERSION docker compose -f compose.headless.yml pull
RUSTNET_IMAGE_TAG=VERSION docker compose -f compose.headless.yml up -d --no-build

# 状態と出力を確認
docker compose -f compose.headless.yml ps
docker compose -f compose.headless.yml logs -f rustnet

# コンテナを残して停止し、その後デプロイをアンインストール
docker compose -f compose.headless.yml stop
docker compose -f compose.headless.yml down
```

Compose には個別の install や enable 手順はありません。イメージのビルドでデプロイを
準備し、`down` でコンテナとネットワークを削除します。最初に明示的に起動した後は、運用者が停止
しない限り、`restart: unless-stopped` によって障害時や Docker daemon 再起動後にコンテナが
再起動します。スナップショットストリームはコンテナの stdout に残り、Docker が付属の
上限付きログポリシーを適用します。

スナップショットをファイルとして永続化する場合は、非公開のホスト volume を追加し、
`command` に `--output-file` を渡してホスト側のローテーションを設定します。read-only
コンテナ内では出力パスだけを書き込み可能にし、より広い capability は追加しないでください。
