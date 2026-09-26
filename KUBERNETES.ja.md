# Kubernetes とコンテナのキャプチャ

[English](KUBERNETES.md) | [简体中文](KUBERNETES.zh-CN.md)

## Docker、Podman、LXC（未リリース）

Linux のコンテナ識別は `kubernetes` 機能やデーモンソケットを必要とせず、プロセスの cgroup と eBPF が保持したソケット情報を使います。ホスト PID、cgroup、ネットワークの可視性が必要です。未知の構成は不明のままで、procfs では終了済みプロセスを復元できません。

Details にランタイム、ID、取得できた名前を表示します。`runtime:docker`、`runtime:podman`、`runtime:lxc`、`container:web` で絞り込めます。`cont:` も名前や ID に一致し、Kubernetes コンテナも検索します。bridge/veth トラフィックには `-i any` を使用します。

Docker と Podman の名前は権限を落とす前に読めたローカルメタデータから取得し、LXC は cgroup 名を ID と名前に使います。独自の保存先や別ユーザーの rootless コンテナなどでは、名前が不明、または再起動まで更新されない場合があります。

ヘッドレス JSON、JSONL ログ、PCAP サイドカーの `container` は `runtime`、`id`、`name`、`cgroup_path` を含み、後者二つは null の場合があります。PCAPNG コメントは `runtime=`、`container_id=`、取得できた場合は `container=` を含みます。イベントは書き込み時点の情報、PCAP サイドカーは終了時に追跡中の接続の最終情報を出力します。

## 短い接続（未リリース）

Linux eBPF と cgroup v2 を使用する場合、RustNet は socket イベントの時点でコンテナと親 pod の cgroup 名を保持します。標準的な systemd と cgroupfs の Kubernetes 構成では、5 秒間隔の名前空間スキャンの間に接続が開始して終了しても、プロセス終了後に所有者を特定できます。検索は観測したエンドポイントの方向（送信元アドレスのワイルドカードを含む）を先に確認し、その後に逆方向を試すため、ホストでのキャプチャでも pod のネットワーク名前空間内の socket を照合できます。Pod とコンテナの名前は既存の kubelet ログのメタデータから解決します。イベントに記録された pod UID とコンテナ ID は、PID ごとのキャッシュより優先されます。

Socket マップは最大 32,768 個の接続タプルを保持し、容量が不足すると古い記録を破棄します。既存のクリーンアップは 30 秒間隔で、60 秒より古い記録を削除します。同じタプルの新しいイベントは所有者情報を置き換えます。保持したイベントはキャプチャ済みパケットの所有者特定に使われ、取り逃したパケットを復元するものではありません。イベントには 2 つの cgroup 名だけが含まれるため、この情報源を使う場合は `cgroup_path` を省略します。

Cgroup v1、コンテナ配下の入れ子の cgroup、eBPF が利用できない環境、読み取れないか切り詰められた cgroup 名では、引き続き procfs スキャンに依存し、スキャンの間に終了するプロセスを取り逃す場合があります。読みやすい名前の解決には kubelet ログのメタデータが必要です。

## エクスポートの後続作業

kubectl プラグインは別のリポジトリ [domcyrus/kubectl-rustnet](https://github.com/domcyrus/kubectl-rustnet) で管理されています。連携する [`--output-dir` の後続タスク](https://github.com/domcyrus/kubectl-rustnet/issues/20) では、キャプチャを正常に停止し、JSONL または PCAPNG の証拠ファイル（sidecar を含む）をフラッシュしてコピーした後に、デバッグ pod を削除する必要があります。コピーが失敗した場合は pod を保持し、復旧手順を表示します。

このオプションはプラグインで計画中の機能であり、今回の RustNet の変更には実装されていません。対応版が出るまでは、セッションを終了する前に、デバッグ pod が動作している間に `kubectl cp` でファイルをコピーしてください。Kubernetes の設定は[使用ガイド（英語）](USAGE.md#--kubernetes-mode-optional-feature)を参照してください。
