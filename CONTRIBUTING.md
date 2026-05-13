# Contributing to RustNet

Pull requests are very welcome! Whether you're fixing bugs, adding features, improving documentation, or providing feedback, all contributions help make RustNet better.

## Project Scope

RustNet aims to stay small and fast. Not every protocol or feature belongs in the core tool, even when a contribution is well-written.

For Deep Packet Inspection in particular, we lean toward protocols that:

- A meaningful share of RustNet users will actually encounter on their networks.
- Produce visible, useful information (the plaintext window is wide enough to extract real metadata, not just to confirm the protocol exists before everything goes TLS).
- Fit the existing architecture without disproportionate maintenance cost.

If a protocol is rarely seen in modern traffic, almost always TLS-wrapped, or niche to a single user base, we may still close the PR with thanks even if the code is correct. Please open an issue first for any new protocol so we can sanity-check fit before you invest implementation time.

## Development Workflow

We use the standard open-source fork and feature branch approach:

1. **Open an issue first** to discuss your proposed changes. For features and non-trivial refactors, please wait for a maintainer response before writing code. Typo fixes, small bug fixes, and documentation corrections do not need a prior issue.
2. Fork the repository
3. Clone your fork locally
4. Create a feature branch from `main` (`git checkout -b feature/your-feature`)
5. Make your changes
6. Push to your fork (`git push origin feature/your-feature`)
7. Open a Pull Request against `main` and reference the related issue

## Code Quality Requirements

Before submitting a PR, please ensure:

- **Unit tests**: Add tests for complex or critical code paths
- **No dead code**: Remove unused code, imports, and dependencies
- **Code style**: Follow the existing code style and patterns in the codebase
- **Clippy**: Fix all clippy warnings
  ```bash
  cargo clippy --all-targets --all-features -- -D warnings
  ```
- **No clippy suppression**: Do not use `#[allow(clippy::...)]` to suppress warnings. Fix the underlying issue instead (e.g., reduce arguments, refactor code). If a suppression is truly unavoidable, discuss it in the PR.
- **Formatting**: Run the formatter
  ```bash
  cargo fmt
  ```
- **Security audit**: Check for known vulnerabilities in dependencies
  ```bash
  cargo audit
  ```

## CI Checks

When you open a PR, our CI pipeline will automatically run checks including:

- Clippy lints
- Code formatting verification
- Build on multiple platforms
- Test suite

Please ensure all CI checks pass before requesting a review.

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
- Verify locally before opening the PR. The PR template lists the exact commands.

## Duplicate Pull Requests

If two or more PRs address the same issue, the maintainers will evaluate them on their merits (code quality, test coverage, architectural fit) rather than submission order. The PR that best fits the project will be merged; others will be closed with thanks. If your PR is closed in favor of another, useful pieces from your work (documentation, tests, edge cases) may be ported over and credited.

To avoid duplicate work, please comment on the linked issue stating that you intend to work on it before you start writing code.

## AI-Assisted Contributions

AI-assisted contributions are welcome, provided you treat the output as your own work and take responsibility for it.

If you use an AI assistant (Copilot, Claude, ChatGPT, Cursor, or similar) to help write code or documentation:

- **Read every line** you are submitting. You are accountable for it.
- **Run the verification commands** listed in the PR template yourself. Do not submit code with a note that tests "could not be run locally" and ask the reviewer to verify.
- **Make sure the PR description matches the code.** If the model wrote the PR body, confirm it describes what the diff actually does.
- **Do not split a single change into many cosmetic per-file commits** to make the work look incremental. One logical change, one commit, with a real commit message.
- **Do not open a PR seconds after filing the issue that motivates it.** Allow time for the maintainers and other contributors to weigh in on the proposed approach.

PRs that show signs of unreviewed AI output (failing tests, fabricated APIs, unrelated bundled changes, mismatched descriptions) will be closed.

## Questions?

Feel free to open an issue if you have questions or want to discuss a potential contribution before starting work.
