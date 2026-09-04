<p align="center"><a href="SERVICE.md">English</a> | <a href="SERVICE.zh-CN.md">简体中文</a> | <strong>日本語</strong></p>

# Linux ヘッドレスサービスの設定例

RustNet パッケージは systemd ユニットをドキュメント例として配布します。
パッケージのインストールや更新では、サービスの登録、有効化、起動、再起動は
行いません。管理者が明示的にコピーして設定します。このガイドは systemd
246 以降と Linux 5.8 以降を対象とし、Windows、macOS、FreeBSD のサービスは
インストールしません。

この例は Linux の全インターフェースを監視し、5 秒ごとにバージョン付きの
JSONL スナップショットを出力します。完全な接続イベント履歴ではなく、最新の
状態です。出力が遅れると途中のスナップショットが省略される場合があります。
[ヘッドレス形式](https://github.com/domcyrus/rustnet/blob/main/USAGE.md#headless-mode)を参照してください。別の機能である
`--json-log` は接続イベントを記録し、stdout のスナップショットは保存しません。

## インストールと有効化

インストール方法に応じて設定例を探してください。

| インストール方法 | ユニットの設定例 |
| --- | --- |
| リリース版 DEB または RPM | `/usr/share/doc/rustnet-monitor/examples/rustnet-headless.service` |
| Debian ソースパッケージまたは PPA | `/usr/share/doc/rustnet/examples/rustnet-headless.service` |
| ネイティブ RPM パッケージ | `/usr/share/doc/rustnet/rustnet-headless.service` |
| openSUSE RPM パッケージ | `/usr/share/doc/packages/rustnet/rustnet-headless.service` |
| Linux リリースアーカイブまたはソース | `resources/packaging/linux/systemd/rustnet-headless.service` |

展開した Linux アーカイブまたはソースディレクトリで実行します。

```bash
sudo install -m 0644 resources/packaging/linux/systemd/rustnet-headless.service \
  /etc/systemd/system/rustnet-headless.service
# バイナリが /usr/bin/rustnet にない場合は ExecStart を変更します。
sudo systemctl edit --full rustnet-headless.service
sudo systemd-analyze verify /etc/systemd/system/rustnet-headless.service
sudo install -d -m 0700 -o root -g root /var/lib/rustnet
sudo systemctl daemon-reload
sudo systemctl enable --now rustnet-headless.service
sudo systemctl status rustnet-headless.service
```

systemd は `StateDirectory` の準備より先に stdout を開く場合があるため、
初回起動前にディレクトリを明示的に作成します。パッケージを使う場合は、
最初のコマンドのコピー元を対応するパスに変更します。
管理者の対話用アカウントでサービスを実行しないでください。ユニットは
`SUDO_UID`、`SUDO_GID`、`SUDO_USER` を消去し、root でキャプチャと eBPF
リソースを開きます。その後 RustNet はトラフィック解析の前に `nobody` に
権限を落とします。この切り替えに失敗すると、トラフィック解析前に起動を
中止します。原因は journal ログで確認してください。
キャプチャ、eBPF 初期化、ユーザー切り替えに必要な
capability だけを許可し、`CAP_SYS_ADMIN` は与えません。eBPF が使えない
場合、権限を落とした後の procfs では一部のプロセスしか見えません。プロセス
帰属に依存する前に、スナップショットの検出方式を確認してください。

RustNet のサンドボックスは有効なままです。プライベートな状態ディレクトリと
一時領域以外は読み取り専用にし、ホームディレクトリは非表示にします。独自の
設定や GeoIP データベースは適切なシステムの場所に置き、明示的なパスを指定
してください。出力先を書き込み可能にするためにサンドボックスを無効化したり、
ディレクトリ権限を広げたりしないでください。

## 出力、停止、保存期間

systemd は権限を落とす前に `/var/lib/rustnet/headless.jsonl` を開きます。
親ディレクトリは root 所有でモード `0700`、新しい出力ファイルは `0600`
です。プロセスは開いた stdout の記述子を保持します。診断情報は journal に
分離するため、大きなスナップショット行の分割や、診断テキストによる JSONL
ストリームの破損を避けられます。

```bash
# スナップショットと診断を別々に確認します。
sudo tail -n 1 /var/lib/rustnet/headless.jsonl | jq .
sudo journalctl -u rustnet-headless.service -n 50
# SIGTERM で時間制限付きの終了処理と最終レコードの出力を要求します。
sudo systemctl stop rustnet-headless.service
```

スナップショットには機密性のあるネットワークやプロセスの情報が含まれます。
アクセスを制限し、ディスクの空き容量を監視して保存期間を決めてください。
再起動後も追記し、自動ローテーションは行いません。書き込み中のレコードを
切り詰めずに切り替えるには、停止後にプライベートディレクトリ内でファイル名
を変更して再開します。この間には短い監視の空白が発生します。

```bash
sudo systemctl stop rustnet-headless.service
sudo mv /var/lib/rustnet/headless.jsonl \
  /var/lib/rustnet/headless-$(date +%Y%m%d-%H%M%S).jsonl
sudo systemctl start rustnet-headless.service
```

無損失の保存を保証するために `copytruncate` を使わないでください。SIGHUP
はファイルを開き直す操作ではなく、ヘッドレス監視を停止します。パッケージの
更新は管理者がコピーしたユニットを変更しません。更新された例を確認し、
バイナリ更新後は明示的に再起動します。アンインストール前に
`sudo systemctl disable --now rustnet-headless.service` を実行し、コピー
したユニットを削除してから `sudo systemctl daemon-reload` を実行します。
保存データは明示的に削除するまで残ります。

## 端末を割り当てずに Docker を実行

Linux ホストでは既存のイメージから `-t` や `-i` なしで出力できます。

```bash
umask 077
docker run --rm --name rustnet-headless --net=host --stop-timeout 30 \
  ghcr.io/domcyrus/rustnet:latest \
  --headless --interface any --refresh-interval 5000 --output jsonl \
  > headless.jsonl
```

呼び出し元のシェルがプライベートな出力ファイルを作成するため、書き込み可能
なホストディレクトリをコンテナにマウントする必要はありません。stderr は
別に表示されます。別の端末から `docker stop rustnet-headless` を実行すると
SIGTERM を送り、最終出力まで最大 30 秒待ちます。Docker Desktop のホスト
ネットワークは、ネイティブ Linux と同じホストキャプチャ動作ではありません。

既定のイメージは非 root ユーザーと `CAP_NET_RAW` でキャプチャします。
ホストネットワークだけではホストのプロセス情報は見えません。eBPF やホストの
プロセス情報には追加権限が必要なので、アクセスを広げる前に
[Docker インストールガイド](https://github.com/domcyrus/rustnet/blob/main/INSTALL.md#using-docker)を確認してください。
Docker のログドライバーにはレコードサイズや保存期間の制限がある場合が
あります。正確な JSONL ストリームには上記の stdout リダイレクトを使い、
出力ファイルの容量と保存期間を管理してください。
