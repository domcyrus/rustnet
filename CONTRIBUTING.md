# Contributing to rustnet

Pull requests are very welcome! Whether you're fixing bugs, adding features, improving documentation, or providing feedback, all contributions help make rustnet better.

## Development Workflow

We use the standard open-source fork and feature branch approach:

1. **Open an issue first** to discuss your proposed changes (for non-trivial work)
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

## Questions?

Feel free to open an issue if you have questions or want to discuss a potential contribution before starting work.
