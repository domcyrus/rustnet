# Windows Npcap loader validation

English | [简体中文](#简体中文) | [日本語](#日本語)

Status: validation tooling only. The production loader is unchanged and the
Windows runtime checks have not been run. Do not consider S1 fixed until the
loader change passes these checks on Windows.

Portable checks of the validator's pass/fail decisions run with
`python -B scripts/windows-npcap/test_verify.py` and in the Windows build action.
They cover module substitution, missing module observations, marker execution,
startup failure, unhealthy snapshots, and missing-runtime diagnostics. They do
not execute the Windows loader.

The current `SetDllDirectoryW` plus `LoadLibraryW("wpcap.dll")` sequence still
searches the executable directory first. Exploitation requires directory write
access and a subsequent launch, possibly elevated before sandboxing. This is
not a remote packet attack. A protected installation directory reduces exposure.

The intended change is to derive the Npcap directory using
`GetSystemDirectoryW`, explicitly load `Packet.dll` and then `wpcap.dll` by
absolute path with `LoadLibraryExW` and
`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`, and retain
both handles for the process lifetime. Fail startup if either load fails, with
no bare-name fallback. Preserve the existing delayed imports and early
`--help`/`--version` handling. The flags restrict dependency searches for that
load operation; they do not automatically secure future delayed loads. Verify
that later Npcap calls reuse the retained modules, and inspect any additional
delayed dependencies exercised by startup and capture.

Run in an elevated MSVC Developer Command Prompt on disposable Windows hosts,
using Python, the compiler, and the release binary with matching architectures.
Run the matrix for both shipped targets, x64 and x86. On one host install Npcap
with its default settings and a working capture adapter; on the other leave
Npcap absent. Build the candidate executable from the exact revision under test.
The script never installs, removes, or replaces system DLLs.

```text
python scripts/windows-npcap/verify.py target/x86_64-pc-windows-msvc/release/rustnet.exe --npcap installed
python scripts/windows-npcap/verify.py target/x86_64-pc-windows-msvc/release/rustnet.exe --npcap absent
```

Use `i686-pc-windows-msvc` with x86 Python and an x86 developer prompt for the
32-bit runs. First run against the current loader to confirm the regression
check fails for an executable-directory marker, then run against the candidate.

The script compiles a benign DLL whose only action is to write a marker file,
and verifies that action in a separate positive-control process. Each runtime
case starts a fresh executable copy. It tests clean startup, each DLL separately
and both together in the executable directory, current directory, and PATH,
and all three locations simultaneously. It also checks help/version with
markers present and checks the PE delay-import table using the existing
validator. Installed-runtime cases must complete a healthy headless capture
and observe both Npcap modules at the intended system paths. Absent-runtime
cases must fail with the missing-Npcap diagnostic. Any marker execution fails.

Evidence is retained in the printed temporary directory: binary and runtime
DLL hashes, OS version, import table, per-case module paths, stdout/stderr, and
the result summary. The marker deliberately has no capture exports, so an
attempted dependency substitution may fail import resolution before its entry
point runs; a failed installed-runtime startup also fails the check. Module
polling cannot prove the absence of every briefly loaded module. Supplement
these results with a Windows image-load trace (for example, Process Monitor)
for startup and capture, and verify every Npcap load path. Also smoke-test the
interactive TUI. Retain that evidence before applying the production fix.

References: Microsoft's [SetDllDirectoryW search order](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setdlldirectoryw)
and [LoadLibraryExW flags](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw).

## 简体中文

状态：仅添加验证工具，生产加载器未更改，尚未在 Windows 上运行验证。
加载器修复必须通过 Windows 验证后，才能认为 S1 已解决。
`python -B scripts/windows-npcap/test_verify.py` 可在其他平台验证判定逻辑，
Windows 构建流程也运行这些测试；它们不执行 Windows 加载器。
当前搜索顺序仍优先查找可执行文件目录。攻击需要对该目录的写权限及之后的
程序启动，可能在提权后、沙箱启用前执行；这不是远程数据包攻击。
使用受保护的安装目录可降低风险。

拟议修复：使用 `GetSystemDirectoryW` 获取系统路径，依次通过绝对路径和
`LoadLibraryExW` 的 `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`
标志加载 `Packet.dll` 与 `wpcap.dll`，并在进程整个生命周期保留两个句柄。
任一加载失败时终止启动，不回退到按名称搜索。保留延迟导入及提前处理的
`--help`/`--version`。这些标志仅约束当前加载操作；必须验证后续延迟导入
复用已加载模块，并检查启动及捕获中触发的其他延迟依赖。

在临时 Windows 测试环境中，以管理员身份打开 MSVC 开发者命令提示符。
Python、编译器与程序的架构必须一致；分别验证 x64 与 x86。
在默认安装 Npcap 且捕获接口可用的主机上运行上方 `--npcap installed` 命令，
在未安装 Npcap 的另一主机上运行 `--npcap absent`。x86 使用
`i686-pc-windows-msvc` 路径。脚本不修改系统 DLL。
先确认现有加载器在可执行文件旁放置标记 DLL 时测试失败，再验证候选修复。

脚本验证标记 DLL 的正向对照，并分别及同时在程序目录、当前目录和 PATH
放置两个 DLL，检查正常捕获、缺失依赖提示、帮助、版本及延迟导入表。
已安装场景要求捕获正常结束，且两个模块均来自预期系统目录。
临时目录保留哈希、系统版本、模块路径和诊断结果。标记 DLL 不导出捕获函数，
因此依赖替换也可能在入口点执行前导致启动失败，该结果同样判为失败。
模块轮询无法排除所有短暂加载，仍需 Windows 映像加载跟踪（例如 Process Monitor）
及交互界面冒烟测试；在应用生产修复前保存这些证据。

## 日本語

状態：検証ツールのみを追加しています。製品のローダーは未変更で、Windows
での実行検証も未実施です。修正が Windows 検証に合格するまで S1 は未解決です。
`python -B scripts/windows-npcap/test_verify.py` で判定ロジックを他の OS でも
検証できます。Windows ビルドでも実行しますが、Windows ローダーは実行しません。
現在の検索順序では実行ファイルのディレクトリが優先されます。攻撃にはその
ディレクトリへの書き込み権限と、その後の起動が必要です。昇格した権限で
サンドボックス適用前に実行される可能性があります。リモートのパケット攻撃では
ありません。保護されたインストール先を使用するとリスクが下がります。

修正案は `GetSystemDirectoryW` からシステムパスを取得し、絶対パスと
`LoadLibraryExW` の `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`
を使って `Packet.dll`、`wpcap.dll` の順にロードし、両ハンドルをプロセス終了まで
保持することです。失敗時は名前だけの検索に戻らず、起動を中止します。
遅延インポートと `--help`/`--version` の早期処理を維持します。フラグの効果は
そのロード操作に限られるため、後続の遅延インポートが保持済みモジュールを
再利用することと、起動・キャプチャ中の追加の遅延依存関係を検証します。

使い捨ての Windows 検証環境で、管理者の MSVC 開発者コマンドプロンプトを
使用してください。Python、コンパイラ、バイナリのアーキテクチャを揃え、x64 と
x86 の両方を確認します。既定の設定で Npcap をインストールし、キャプチャ可能な
アダプターがある環境で上記の `--npcap installed`、未インストールの別環境で
`--npcap absent` を実行します。x86 は `i686-pc-windows-msvc` を使用します。
スクリプトはシステム DLL を変更しません。まず既存ローダーで実行ファイル横の
マーカーが検出されてテストが失敗することを確認し、次に修正候補を検証します。

スクリプトは無害なマーカー DLL の動作を正の対照で確認し、実行ファイルの
ディレクトリ、現在のディレクトリ、PATH に各 DLL を個別または同時に配置して
検証します。正常なキャプチャ、Npcap 不在時の診断、ヘルプ、バージョン、遅延
インポート表を確認します。インストール済みの場合は正常終了と両モジュールの
正しいシステムパスを必須とします。一時ディレクトリにハッシュ、OS バージョン、
モジュールパス、診断を保存します。マーカーにはキャプチャ関数のエクスポートが
ないため、エントリーポイントより前に依存解決が失敗する場合もあり、これも
テスト失敗になります。ポーリングでは短時間のロードをすべて検出できないため、
Windows のイメージロードトレース（例：Process Monitor）と対話画面の動作確認も
実施し、製品の修正を適用する前に証拠を保存してください。
