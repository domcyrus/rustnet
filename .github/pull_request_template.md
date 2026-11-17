<!--
Thanks for contributing to rustnet. Please read CONTRIBUTING.md before
opening the PR, then fill in the sections below.

CONTRIBUTING.md: https://github.com/domcyrus/rustnet/blob/main/CONTRIBUTING.md

Fill in the sections that apply to your change; remove the rest.
-->

## Summary

<!-- What does this PR do, and why? A few sentences are enough.
For performance changes, explain the benefit and include evidence
appropriate to the claim (see CONTRIBUTING.md#performance--optimizations). -->

## Linked issue

<!-- Optional: link related issues or use "Closes #123" when appropriate.
Small, focused changes do not need a prior issue. For substantial features,
new protocols, or architectural refactors, discussion first is recommended. -->

## Verification

<!-- Describe the checks you ran and their results. The commands below are
the standard checks for code changes. Remove checks that do not apply;
explain any relevant checks you could not run and why. For documentation-only
changes, check wording, links, and translations; Rust builds and tests are
not required. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --workspace --all-features`
- [ ] `cargo build --locked --workspace --all-targets --release`
- [ ] `cargo audit` (dependency changes)

## Scope

- [ ] One feature or fix per PR (no unrelated cleanups bundled in)
- [ ] I reviewed the changes and the description matches the diff
- [ ] No new dependencies, or rationale provided in the summary above
- [ ] No `#[allow(clippy::...)]` suppressions, or rationale provided
  (see [CONTRIBUTING.md](https://github.com/domcyrus/rustnet/blob/main/CONTRIBUTING.md#code-quality-requirements))
- [ ] User-visible changes are added to the `## [Unreleased]` section of
  `CHANGELOG.md` in this PR, or this change is not user-visible
  (see [CONTRIBUTING.md](https://github.com/domcyrus/rustnet/blob/main/CONTRIBUTING.md#pr-guidelines))

## Notes for the reviewer

<!-- Anything that would help review: tricky edge cases, deliberate
trade-offs, follow-up work you plan to do in a separate PR. -->
