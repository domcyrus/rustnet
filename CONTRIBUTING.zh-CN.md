<p align="center"><a href="CONTRIBUTING.md">English</a> | <strong>简体中文</strong> | <a href="CONTRIBUTING.ja.md">日本語</a></p>

# 参与贡献

欢迎提交 Pull Request！无论你是修复 bug、添加功能、改进文档，还是提供反馈，所有贡献都能让 RustNet 变得更好。

## 项目范围<a id="project-scope"></a>

RustNet 追求小而快。并不是每个协议或功能都适合放在核心工具里，即使贡献的代码写得很好。

对于深度包检测（DPI），我们倾向于满足以下条件的协议：

- RustNet 用户中有相当一部分会在自己的网络中实际遇到。
- 能提取出可见且有用的信息（明文窗口足够宽，能提取出真正的元数据，而不仅仅是确认协议存在就进入 TLS）。
- 能以合理的维护成本融入现有架构。

如果某个协议在现代流量中很少见、几乎总是包裹在 TLS 里，或者仅服务于单一小众用户群，即使代码正确，我们也可能婉拒该 PR。对于新协议，建议在投入大量实现时间之前，先通过 issue 讨论其是否适合本项目。

## 性能与优化<a id="performance-optimizations"></a>

欢迎性能改进，包括保持代码清晰、易于维护的小型改动。请说明改进的内容，并提供与所声称的收益相称的依据。

- **明确收益范围。** 针对性的基准测试、内存分配测量，或对减少了哪些工作的清晰说明，都可以支持小型优化。微基准测试衡量的是某个操作，而不是整个应用的性能。
- **衡量整体收益。** 如果声称降低了 CPU 或内存使用量、提高了吞吐量或响应速度，请提供在有代表性的负载下可复现的前后对比数据。性能分析（参见 [PROFILING.zh-CN.md](PROFILING.zh-CN.md)）可以帮助定位瓶颈，但并非每个 PR 都需要火焰图。
- **权衡收益与复杂度。** 小型简化不必局限于热点路径。如果改动增加了复杂度，应证明其收益足以抵偿维护成本。

## 开发流程<a id="development-workflow"></a>

我们采用标准的开源 fork 和功能分支方式：

1. **查看现有的 issue 和 PR。** 小而聚焦的改动可以直接提交 PR。对于较大的功能、新协议或架构重构，建议先通过 issue 讨论方案，避免投入不适合本项目的工作。
2. Fork 本仓库
3. 将 fork 克隆到本地
4. 从 `main` 创建功能分支（`git checkout -b feature/your-feature`）
5. 进行你的修改
6. 推送到你的 fork（`git push origin feature/your-feature`）
7. 向 `main` 提交 Pull Request，并链接任何相关的 issue

## 代码质量要求<a id="code-quality-requirements"></a>

对于代码改动，请确保：

- **单元测试**：为复杂或关键的代码路径添加测试
- **无死代码**：删除未使用的代码、导入和依赖
- **代码风格**：遵循代码库中已有的代码风格和模式
- **Clippy**：修复所有 clippy 警告
  ```bash
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
  ```
- **禁止 clippy 抑制**：不要使用 `#[allow(clippy::...)]` 来抑制警告。请修复根本问题（例如减少参数、重构代码）。如果确实无法避免，请在 PR 中说明。
- **格式化**：运行格式化工具
  ```bash
  cargo fmt
  ```
- **测试**：运行整个工作区的测试套件
  ```bash
  cargo test --locked --workspace --all-features
  ```
- **安全审计**：修改依赖时，检查其中的已知漏洞
  ```bash
  cargo audit
  ```

## CI 检查<a id="ci-checks"></a>

当你提交 PR 时，我们的 CI 流水线会自动运行以下检查：

- Clippy lint
- 代码格式化验证
- 多平台构建
- 测试套件

请在合并之前解决适用的 CI 检查中的失败项。检查尚未完成时，也可以提交 PR 征求反馈。

## 依赖策略<a id="dependency-policy"></a>

请谨慎添加依赖：

- 除非有充分的理由，否则不要添加依赖
- 尽可能优先使用标准库方案
- 如果必须添加依赖，请在 PR 描述中说明理由
- 考虑依赖的维护状态和安全记录

## 安全<a id="security"></a>

对于网络监控工具，安全至关重要：

- 编写代码时牢记安全
- 避免引入常见漏洞（注入、缓冲区问题等）
- 谨慎处理用户输入和网络数据解析
- 请负责任地报告安全问题（参见 [SECURITY.zh-CN.md](SECURITY.zh-CN.md)）

## PR 指南<a id="pr-guidelines"></a>

- 清晰描述你的改动做了什么以及为什么
- 链接任何相关的 issue
- 保持 PR 聚焦，每个 PR 只做一件事
- 及时响应 review 反馈
- 审阅并理解你提交的改动，确保描述与 diff 一致。
- 运行与改动相关的检查。PR 模板列出了代码改动的标准命令。请说明运行了哪些检查，以及哪些未能运行及其原因。仅修改文档时，检查措辞、链接和翻译即可，无需运行 Rust 构建和测试。
- 在同一个 PR 中把用户可见的改动写入 `CHANGELOG.md` 的 `## [Unreleased]` 小节

## 文档<a id="documentation"></a>

- 保持 README 简洁：简短介绍、主要安装方式、演示动画和截图、少量功能亮点，以及详细指南的链接。不要在 README 中加入冗长的功能列表、安装细节、命令行参考或实现细节。
- 将详细内容写入相应指南（`INSTALL.zh-CN.md`、`USAGE.zh-CN.md`、`SECURITY.zh-CN.md` 或 `ARCHITECTURE.zh-CN.md`），适用时从 README 链接到这些指南。
- 不要在 README 的功能亮点或媒体中将未发布功能描述为已可用。在指南和 `CHANGELOG.md` 中标明仅限开发版本的内容；发布新版本时，更新三个语言版本 README 的版本说明和功能描述，并保持内容一致。

## 重复 Pull Request<a id="duplicate-pull-requests"></a>

如果两个或多个 PR 解决了同一个 issue，维护者将根据代码质量、测试覆盖率和架构契合度来评估，而不是提交顺序。最符合项目需求的 PR 将被合并；其他 PR 将被关闭并致谢。如果你的 PR 被另一个替代，你工作中的有用部分（文档、测试、边界情况）可能会被移植并给予署名。

查看现有 PR，并在相关 issue 中分享你的计划，有助于避免重复工作。

## AI 辅助贡献<a id="ai-assisted-contributions"></a>

欢迎使用 AI 辅助贡献，其适用标准与其他贡献相同。你需要负责理解和审阅改动、按照上述要求进行验证，并回应反馈。可以使用任何有助于产出清晰、正确且易于维护的贡献的工具。

## 有问题？<a id="questions"></a>

如果你有任何问题，或者想在开始工作之前讨论潜在的贡献，欢迎随时开一个 issue。
