<p align="center"><a href="USAGE.md">English</a> | <a href="USAGE.zh-CN.md">简体中文</a> | <strong>日本語</strong></p>

# 使用ガイド

`main` の文書には未リリース機能も含まれます。`rustnet --version` と `rustnet --help` で
インストール済みバージョンと利用可能なオプションを確認してください。
全オプション、フィルター、無画面モード、エクスポートは[詳細ガイド（英語）](USAGE.md)を参照してください。

## 基本操作

権限の設定は[インストールガイド（英語）](INSTALL.md)を参照してください。
`rustnet` で起動し、必要なら `-i <interface>` でキャプチャ対象を指定します。

- `1`～`5` または Tab / Shift+Tab：Overview、Details、Activity、Graph、Host の切り替え。
- `/`：接続の絞り込み。Enter：選択した接続の詳細。Esc：戻る。
- `h`：現在の画面のヘルプ。`q`：終了。

## 小さい端末での表示<a id="compact-terminals"></a>

全体が収まらない場合は `v` / Shift+`v` または見出しのクリックでセクションを切り替えます。
Host では常に同じ操作で Sockets、Interfaces、DNS を選択します。
Details では長いセクションのページも切り替え、`j` / `k` とマウスホイールで接続を選びます。
端末のサイズ変更や接続の切り替え後も選択中のセクションを保ちます。

Host の Sockets と Interfaces は表が収まらない場合に折り返し表示を使います。
`j` / `k`、矢印キー、Page Up/Down、`g` / `G`、ホイールでスクロールできます。
小さい Overview では Esc で System から Connections に戻り、広い端末では `i` で
System サイドバーを切り替えます。各画面の操作は `h` で確認できます。

## 転送グラフ<a id="traffic-charts"></a>

Graph は選択したキャプチャ対象のカウンターを使います。`any` と macOS 標準の `pktap` は
全インターフェースの合計で、同じ通信を複数回数える場合があります。
カウンターが取得できない間は RX/TX グラフを停止し、サンプルの取得後に再開します。

Graph と Details は観測したバーストを保持し、RX/TX 別の自動線形目盛りを使います。
単位はバイト/秒（KiB/MiB/GiB は二進単位）なので、方向間の比較は数値で行ってください。
余裕があれば現在値、期間内のピーク、`2s avg` を表示します。`0 B/s` は観測したアイドル状態、
プレースホルダーはデータなしを示します。Details と Top Processes は平滑化した接続速度、
Graph はインターフェース速度を使います。

Activity は `s` で `2s Avg TX/RX` 順、`d` で TX/RX を選択します。
割合の棒は直近 60 秒が対象で、仮想/VPN インターフェースの割合は重複する場合があります。
Overview のフィルターと履歴切り替えは Activity を制限しません。DNS 解決が有効な場合、
両画面とも `--show-ptr-lookups` を指定しない限り PTR 通信を非表示にします。

## Host とネットワークイベント<a id="host-socket-inventory"></a>

Host > Sockets は OS の TCP 状態、UDP バインド、待受端点と所属プロセスを表示し、
5 秒ごとに更新します。パケットを観測していないソケットも表示します。
Linux ではサンドボックス適用後も、同一ソケットの起動時の所属情報を保持します。
共有ソケット、終了したプロセス、識別情報の変化、権限不足では所属不明になる場合があり、
新規ソケットの所属取得には引き続き procfs へのアクセスが必要です。

### 観測したネットワークイベント（未リリース）<a id="observed-network-events-unreleased"></a>

Host > Sockets は TCP リセットと ICMPv4/v6 エラーの送信/受信数を表示します。
対象は到達不能、禁止、パケット過大/フラグメント化要求、時間超過、パラメーター異常です。
起動またはクリア以降の捕獲した通信を集計し、表示フィルターや接続保持期間には依存しません。
ファイアウォール判定や OS 全体のカウンターではなく、MTU や traceroute の応答は正常な場合もあります。

Details > Health は件数と最新エラーのタイプ/コード、報告元、方向、経過時間、取得できた通知 MTU を表示します。
引用された端点で TCP/UDP 接続に対応付け、接続状態や通信量は変更しません。
不完全な引用、フラグメント、IPv6 拡張、NAT、接続の不在や再利用で対応付け不能・誤対応になる場合があります。
未対応のエラーも Host で集計し、エラー履歴は保持しません。

`--json-log` の受信 `new_connection` には `local_port_status` も含まれます（未リリース）。
キャッシュ内の TCP 待受/UDP バインドに一致すれば `opened`、観測されなければ `closed`、
取得・更新失敗や曖昧なワイルドカードは `unknown` です。既知の TCP 握手方向を優先し、
不明なら最初のパケットの方向を使います。5 秒の更新間隔と OS の可視範囲に制限され、ファイアウォール判定ではありません。

## 表示設定

設定ファイルは `~/.config/rustnet/config.toml`（`XDG_CONFIG_HOME` 指定時はその配下）、
Windows は `%APPDATA%\rustnet\config.toml` です。以下はどちらも任意で、既定値は `false` です。

```toml
[ui]
popup_shadow = true

[view]
group_by_process = true
```

`popup_shadow` はヘルプの影を有効にします。`NO_COLOR` または `--no-color` で無効になります。
`group_by_process` は Overview を折りたたんだプロセス別グループで開始します。
`a` で一時的に切り替え、Space で展開し、`r` で設定値に戻します。無画面出力には影響しません。
