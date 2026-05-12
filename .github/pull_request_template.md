<!--
Thanks for contributing to rustnet. Please read CONTRIBUTING.md before
opening the PR, then fill in the sections below.

CONTRIBUTING.md: https://github.com/domcyrus/rustnet/blob/main/CONTRIBUTING.md

PRs that ship without the checklist completed will usually be asked to
update before review.
-->

## Summary

<!-- What does this PR do, and why? One or two paragraphs. -->

## Linked issue

<!-- For features and non-trivial changes, link the issue where the
approach was discussed. If there is no issue, please open one first
(see CONTRIBUTING.md: https://github.com/domcyrus/rustnet/blob/main/CONTRIBUTING.md#development-workflow).
Bug fixes and typo corrections do not need a prior issue. -->

Closes #

## Verification

Per [CONTRIBUTING.md > Code Quality Requirements](https://github.com/domcyrus/rustnet/blob/main/CONTRIBUTING.md#code-quality-requirements),
I ran the following locally and they all pass:

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] `cargo build --release`

<!-- If any of these did not run, say which and why. CI will also run
them, but local verification catches issues faster. -->

## Scope

- [ ] One feature or fix per PR (no unrelated cleanups bundled in)
- [ ] No new dependencies, or rationale provided in the summary above
- [ ] No `#[allow(clippy::...)]` suppressions, or rationale provided
  (see [CONTRIBUTING.md](https://github.com/domcyrus/rustnet/blob/main/CONTRIBUTING.md#code-quality-requirements))

## AI-assisted contributions

If you used an AI assistant (Copilot, Claude, ChatGPT, Cursor, etc.) to
write any of this code, that is fine, but please confirm:

- [ ] I have read every line I am submitting
- [ ] I ran the verification commands above myself
- [ ] The PR description reflects what the code actually does

## Notes for the reviewer

<!-- Anything that would help review: tricky edge cases, deliberate
trade-offs, follow-up work you plan to do in a separate PR. -->
