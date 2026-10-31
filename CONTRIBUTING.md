<p align="center"><strong>English</strong> | <a href="CONTRIBUTING.zh-CN.md">简体中文</a> | <a href="CONTRIBUTING.ja.md">日本語</a></p>

# Contributing to RustNet

Pull requests are very welcome! Whether you're fixing bugs, adding features, improving documentation, or providing feedback, all contributions help make RustNet better.

## Project Scope

RustNet aims to stay small and fast. Not every protocol or feature belongs in the core tool, even when a contribution is well-written.

For Deep Packet Inspection in particular, we lean toward protocols that:

- A meaningful share of RustNet users will actually encounter on their networks.
- Produce visible, useful information (the plaintext window is wide enough to extract real metadata, not just to confirm the protocol exists before everything goes TLS).
- Fit the existing architecture without disproportionate maintenance cost.

If a protocol is rarely seen in modern traffic, almost always TLS-wrapped, or niche to a single user base, we may still close the PR with thanks even if the code is correct. For new protocols, we recommend discussing fit in an issue before investing substantial implementation time.

## Performance & Optimizations

Performance improvements are welcome, including small changes that keep the code clear and maintainable. Explain what improves and provide evidence appropriate to the claim.

- **Keep claims specific.** A focused benchmark, allocation measurement, or clear explanation of avoided work can support a small optimization. A microbenchmark measures that operation, not overall application performance.
- **Measure broader claims.** For claims about CPU usage, memory use, throughput, or responsiveness, include reproducible before/after measurements under a representative workload. Profiling (see [PROFILING.md](PROFILING.md)) can help identify bottlenecks; a flamegraph is not required for every PR.
- **Balance benefit and complexity.** Small simplifications do not need to be on a hot path. Changes that add complexity should demonstrate enough benefit to justify their maintenance cost.

## Development Workflow

We use the standard open-source fork and feature branch approach:

1. **Check existing issues and PRs.** Small, focused changes can go straight to a PR. For substantial features, new protocols, or architectural refactors, we recommend discussing the approach in an issue first to avoid work that may not fit the project.
2. Fork the repository
3. Clone your fork locally
4. Create a feature branch from `main` (`git checkout -b feature/your-feature`)
5. Make your changes
6. Push to your fork (`git push origin feature/your-feature`)
7. Open a Pull Request against `main` and link any related issues

## Code Quality Requirements

For code changes, please ensure:

- **Unit tests**: Add tests for complex or critical code paths
- **No dead code**: Remove unused code, imports, and dependencies
- **Code style**: Follow the existing code style and patterns in the codebase
- **Clippy**: Fix all clippy warnings
  ```bash
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
  ```
- **No clippy suppression**: Do not use `#[allow(clippy::...)]` to suppress warnings. Fix the underlying issue instead (e.g., reduce arguments, refactor code). If a suppression is truly unavoidable, discuss it in the PR.
- **Formatting**: Run the formatter
  ```bash
  cargo fmt
  ```
- **Tests**: Run the workspace test suite
  ```bash
  cargo test --locked --workspace --all-features
  ```
- **Security audit**: When changing dependencies, check for known vulnerabilities
  ```bash
  cargo audit
  ```

## CI Checks

When you open a PR, our CI pipeline will automatically run checks including:

- Clippy lints
- Code formatting verification
- Build on multiple platforms
- Test suite

Please address failures in applicable CI checks before merging. You can open a PR for feedback while checks are pending.

## Dependency Policy

Please be conservative with dependencies:

- Don't add dependencies unless there's a good reason
- Prefer standard library solutions when possible
- If adding a dependency, explain the rationale in your PR description
- Consider the dependency's maintenance status and security track record

## Security

Security is important for a network monitoring tool:

- Keep security in mind when writing code
- Avoid introducing common vulnerabilities (injection, buffer issues, etc.)
- Be careful with user input and network data parsing
- Report security issues responsibly (see [SECURITY.md](SECURITY.md))

## PR Guidelines

- Write a clear description of what your changes do and why
- Link any related issues
- Keep PRs focused - one feature or fix per PR
- Be responsive to review feedback
- Review and understand the changes you submit, and make sure the description matches the diff.
- Run checks relevant to your changes. The PR template lists the standard commands for code changes. Report what you ran and any checks you could not run, with the reason. For documentation-only changes, check the wording, links, and translations; Rust builds and tests are not required.
- Add user-visible changes to the `## [Unreleased]` section of `CHANGELOG.md` in the same PR

## Documentation

- Keep the READMEs concise: a short introduction, primary installation method, demo and screenshots, brief highlights, and links to detailed guides. Avoid adding long feature lists, setup instructions, CLI references, or implementation details there.
- Put details in the relevant guides (`INSTALL.md`, `USAGE.md`, `SECURITY.md`, or `ARCHITECTURE.md`) and link to them from the README when useful.
- Do not describe unreleased features as available in README highlights or media. Mark development-only information in the guides and `CHANGELOG.md`; update the release note and claims in all three READMEs when a release ships. Keep the English, Chinese, and Japanese READMEs aligned.

## Duplicate Pull Requests

If two or more PRs address the same issue, the maintainers will evaluate them on their merits (code quality, test coverage, architectural fit) rather than submission order. The PR that best fits the project will be merged; others will be closed with thanks. If your PR is closed in favor of another, useful pieces from your work (documentation, tests, edge cases) may be ported over and credited.

Checking existing PRs and sharing your plans on a related issue can help avoid duplicate work.

## AI-Assisted Contributions

AI-assisted contributions are welcome and follow the same standards as any other contribution. You are responsible for understanding and reviewing the changes, verifying them as described above, and responding to feedback. Use whatever tools help you produce a clear, correct, and maintainable contribution.

## Questions?

Feel free to open an issue if you have questions or want to discuss a potential contribution before starting work.
