# RPM packaging

## English

The [spec](rustnet.spec) builds the tagged release. RPM release 2 adds a
Fedora aarch64 build workaround for libbpf 1.7.0: its private `linux/types.h`
lacks the `__s128` and `__u128` types required by Linux 7.3 headers.
`LIBBPF_SYS_EXTRA_CFLAGS` includes the upstream-compatible typedefs only
while compiling libbpf-sys, preserving any existing extra flags.

Remove the workaround once the release's libbpf-sys dependency includes
[upstream fix f90a9c487d75](https://github.com/libbpf/libbpf/commit/f90a9c487d7542d91fa584b83b6a624a4fbeb341).
It does not change the RustNet version or disable eBPF.

## 简体中文

[spec 文件](rustnet.spec) 构建带版本标签的发布源码。RPM release 2 为 Fedora
aarch64 添加了 libbpf 1.7.0 的构建兼容措施：其私有 `linux/types.h` 缺少
Linux 7.3 头文件所需的 `__s128` 和 `__u128` 类型。通过
`LIBBPF_SYS_EXTRA_CFLAGS`，仅在编译 libbpf-sys 时包含与上游一致的类型定义，
并保留已有的额外编译参数。

当发布版本依赖的 libbpf-sys 包含上述上游修复 f90a9c487d75 后，应移除此措施。
此措施不改变 RustNet 版本，也不禁用 eBPF。

## 日本語

[spec ファイル](rustnet.spec) はリリースタグのソースをビルドします。
RPM release 2 は Fedora aarch64 向けに libbpf 1.7.0 のビルド互換処理を追加します。
同梱の `linux/types.h` には Linux 7.3 のヘッダーが必要とする `__s128` と
`__u128` がありません。`LIBBPF_SYS_EXTRA_CFLAGS` で既存の追加フラグを保持し、
libbpf-sys のコンパイル時だけ上流と同じ型定義を読み込みます。

リリースが使用する libbpf-sys に上記の上流修正 f90a9c487d75 が含まれたら、
この互換処理を削除してください。RustNet のバージョンは変更せず、eBPF も無効にしません。
