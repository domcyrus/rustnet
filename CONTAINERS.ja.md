# コンテナの所有者特定（未リリース）

[English](CONTAINERS.md) | [简体中文](CONTAINERS.zh-CN.md)

Linux の開発版は、プロセスの cgroup と eBPF が保持するソケットの cgroup 名から
Docker、Podman、LXC の接続を識別します。`kubernetes` 機能とは独立して動作し、
ランタイムのデーモンソケットには接続しません。Kubernetes Pod の既存フィールドと
動作は維持されます。

## 識別子と名前

- Docker: `/docker/<64 桁の 16 進 ID>`、`docker-<ID>.scope`。
- Podman: `libpod-<64 桁の 16 進 ID>`、`libpod-<ID>.scope`。
  rootless のユーザー slice と cgroupfs レイアウトも対象です。
- LXC: `/lxc/<名前>`、`/lxc.payload/<名前>`、`lxc.payload.<名前>`。
  名前を識別子と表示名の両方に使用します。監視プロセスの cgroup は対象外です。

最も内側のコンテナを優先します。ハッシュだけのパス、未知のレイアウト、見えない
cgroup は不明のままです。基本識別にはプロセスと cgroup の可視性が必要ですが、
ランタイムのメタデータやデーモンソケットへのアクセスは不要です。
eBPF と cgroup v2 では、保持したリーフと親の名前によりプロセス終了後も識別できます。
この二つの名前だけでは識別できない深いサブツリーには、生存するプロセスが必要です。
procfs のフォールバックでは終了済みプロセスを復元できません。

権限を落とす前に、RustNet は読み取り可能な名前をサイズ制限付きで読み込みます。
Docker は `/var/lib/docker/containers` 配下の `config.v2.json`、Podman は
`/var/lib/containers/storage` 配下の `{overlay,vfs,btrfs}-containers/containers.json`
を使用します。起動ユーザーの `XDG_DATA_HOME`（既定は `$HOME/.local/share`）配下の
`docker/containers` と `containers/storage` も確認します。LXC の名前は cgroup から
直接取得します。

名前は任意情報です。独自の保存先、権限制限、起動後の作成や改名、別ユーザーの
rootless ストレージでは、名前が不明、または再起動まで更新されない場合があります。
ランタイムと ID は引き続き利用できます。認証情報や設定全体は出力しません。

## Details、フィルター、エクスポート

Details の **Container** セクションにランタイム、ID、任意の名前と cgroup パスを
表示します。フィルターは他のテキスト項目と同じ部分一致と正規表現を使用します。

```bash
sudo rustnet --filter 'runtime:docker'
sudo rustnet --filter 'runtime:podman container:web'
sudo rustnet --headless --duration 10 --output json --filter 'runtime:lxc'
```

`container:`（別名 `cont:`）は名前または ID に一致し、Kubernetes のコンテナ情報も
引き続き検索します。`runtime:` は `docker`、`podman`、`lxc` に一致します。

ヘッドレスのスナップショットには null 許容の `container` オブジェクトを追加します。
JSONL イベントと PCAP の JSONL サイドカーには、識別できた場合にこの情報を出力します。

```json
{"container":{"runtime":"lxc","id":"web","name":"web","cgroup_path":"/lxc.payload.web"}}
```

`name` と `cgroup_path` は null の場合があります。保持したソケット名には完全な
パスがありません。PCAPNG コメントには `runtime=`、`container_id=`、取得できた場合は
`container=` を出力します。イベントとパケットコメントは書き込み時点の情報です。
PCAP サイドカーは終了時に追跡中の接続の最終メタデータを含みます。

Linux ホスト上で実行するか、監視コンテナにホスト PID、cgroup、ネットワークの可視性を
与えてください。bridge/veth トラフィックには `-i any` を使用します。隔離コンテナや
macOS の Docker クライアントからは Linux ホストの他のコンテナは見えません。
ランタイムソケットのマウントは不要です。
