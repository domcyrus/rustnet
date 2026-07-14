# Release Process

This document is for maintainers releasing new versions of RustNet.

## Changelog Maintenance (ongoing, not at release time)

Notable changes are added to the `## [Unreleased]` section of `CHANGELOG.md` in
the same PR that makes them — don't wait until release time and reconstruct the
list from git history. Cutting a release then just renames that section (see
step 3 below). `pre-release-check.sh` warns if `[Unreleased]` still has content
after the rename, and the release workflow's notes extraction ignores it.

## Creating a New Release

### 1. Run Pre-Release Checks

After updating versions and changelog, run the pre-release validation script:

```bash
./scripts/pre-release-check.sh 1.2.0
```

This validates version consistency, changelog entries, code quality (fmt/clippy/test),
Dockerfile correctness, and git status. Fix any errors before proceeding.

### 2. Test Platform Builds

Before tagging, verify all platform builds succeed on the current main branch:

```bash
# Ensure you're on the main branch with latest changes
git checkout main
git pull origin main
```

1. Go to [Actions > Test Platform Builds](../../actions/workflows/test-platform-builds.yml)
2. Click "Run workflow" (it builds all platforms, including static Linux builds,
   and also triggers a FreeBSD test build in the rustnet-bsd repo)
3. Wait for the workflow to complete successfully

This catches cross-platform and static linking issues before you invest time in release prep.

### 3. Prepare the Release

> **Two version tracks since the workspace split.** `Cargo.toml` carries two
> versions: the binary's `[package] version` (line ~30, the user-facing `1.x`
> line that tags and packages follow) and `[workspace.package] version` (line
> ~9, the `0.x` library crates `rustnet-core`/`-capture`/`-host`, single source
> of truth also referenced from `[workspace.dependencies]`). A normal feature
> release bumps **only the binary `[package] version`** and `rpm/rustnet.spec`.
> Bump the library version separately, and only when the libraries actually
> change in a release-worthy way.

Update the binary version in `Cargo.toml` and `rpm/rustnet.spec`, and turn the
accumulated `[Unreleased]` changelog section into the release entry:

```bash
# Update Cargo.toml [package] version (e.g., version = "1.4.0") — NOT the
#   [workspace.package] version unless you intend to bump the library crates.
# Update rpm/rustnet.spec Version field (e.g., Version: 1.4.0)

# In CHANGELOG.md:
#   1. Rename "## [Unreleased]" to "## [0.3.0] - YYYY-MM-DD" (review/polish the entries)
#   2. Add a fresh, empty "## [Unreleased]" section above it
#   3. Update the comparison links at the bottom:
#        [Unreleased]: https://github.com/domcyrus/rustnet/compare/v0.3.0...HEAD
#        [0.3.0]: https://github.com/domcyrus/rustnet/compare/v0.2.0...v0.3.0

# Update Cargo.lock and test the build
cargo build --release
cargo test
```

### 4. Commit Release Changes

```bash
# Stage and commit the version and changelog changes
git add Cargo.toml Cargo.lock CHANGELOG.md rpm/rustnet.spec
git commit -m "Release v0.3.0

- Feature or fix summary here
- Another change here
- And more changes"
```

### 5. Create and Push Git Tag

```bash
# Create an annotated tag matching the version in Cargo.toml
git tag -a v0.3.0 -m "Release v0.3.0

- Feature or fix summary here
- Another change here
- And more changes"

# Push both the commit and the tag
git push origin main
git push origin v0.3.0
```

**That's it!** The GitHub Actions workflow will automatically:
- Build binaries for all platforms (Linux, macOS, Windows - multiple architectures)
- Create installer packages (DEB, RPM, DMG, MSI)
- Extract release notes from CHANGELOG.md
- Create a draft GitHub release with all artifacts attached
- Upload all binaries and installers to the release
- **Publish the release** (un-draft) once all assets are uploaded
- Trigger downstream package updates (Homebrew, Chocolatey, FreeBSD, PPA, COPR, AUR, Docker, crates.io)

### 6. Verify the Release

Once the GitHub Actions workflow completes (~15-20 minutes):

1. Go to the [GitHub repository releases page](https://github.com/domcyrus/rustnet/releases)
2. Verify the release is published (no longer a draft) with all assets
3. Review the automatically extracted release notes
4. Check downstream package updates completed (Homebrew, Chocolatey, etc.)

## Automated Release Workflow

The release process is fully automated via [`.github/workflows/release.yml`](.github/workflows/release.yml):

**Triggers:**
- Pushing a tag matching `v[0-9]+.[0-9]+.[0-9]+` (e.g., `v0.3.0`, `v1.2.3`)
- Manual workflow dispatch

**What it does:**
1. **Builds cross-platform binaries:**
   - Linux: x64, ARM64, ARMv7 (with eBPF support)
   - macOS: Intel (x64) and Apple Silicon (ARM64)
   - Windows: 64-bit and 32-bit

2. **Creates installer packages:**
   - **Linux:** DEB packages (amd64, arm64, armhf) and RPM packages (x86_64, aarch64)
   - **macOS:** DMG installers with app bundles (supports code signing/notarization if secrets configured)
   - **Windows:** MSI installers (64-bit and 32-bit)

3. **Extracts release notes:**
   - Automatically parses `CHANGELOG.md` to extract the version-specific section
   - Falls back to auto-generated notes if no changelog entry is found

4. **Creates GitHub release:**
   - Creates a draft release with the tag name as title
   - Attaches all binaries and installer packages
   - Uses extracted changelog content as release notes

5. **Publishes the workspace to crates.io** (via
   [`.github/workflows/publish.yml`](.github/workflows/publish.yml), after the
   GitHub release is published): the four crates are published in dependency
   order — `rustnet-core` → `rustnet-capture` → `rustnet-host` →
   `rustnet-monitor` — waiting for each to appear in the index before publishing
   a dependent. The step is idempotent (it skips any `crate@version` already on
   crates.io), so a re-run after a partial failure is safe. The library crates
   use the `[workspace.package]` version; the binary uses its `[package]`
   version.

## Important: Never Move a Tag After Release

**Never force-push or move a tag after the release pipeline has started.** Moving a tag
causes GitHub to regenerate source tarballs with different SHA checksums, which breaks
every downstream package manager that already cached the original checksums:

- **AUR/Homebrew/Chocolatey**: checksum verification failures for end users
- **Launchpad PPA**: rejects uploads with the same version but different file contents
- **crates.io**: already published and cannot be re-published with the same version

If a fix is needed after tagging, **create a patch release** (e.g., `v1.1.1`) instead.

## Release Checklist

Before pushing the tag, ensure:

- [ ] Pre-release checks pass: `./scripts/pre-release-check.sh x.y.z`
- [ ] Test Platform Builds workflow passes for all platforms (including static)
- [ ] Binary version updated in `Cargo.toml` `[package]` (not `[workspace.package]` unless bumping the library crates)
- [ ] Version number updated in `rpm/rustnet.spec` (line 5: `Version: x.y.z`)
- [ ] `Cargo.lock` updated (via `cargo build`)
- [ ] `CHANGELOG.md`: `[Unreleased]` renamed to `## [x.y.z] - YYYY-MM-DD`, a fresh empty `[Unreleased]` added, comparison links updated
- [ ] All tests pass (`cargo test`)
- [ ] Changes committed to main branch
- [ ] Git tag created and pushed

After GitHub Actions completes:

- [ ] Verify release is published (automatically un-drafted after all assets uploaded)
- [ ] Verify all platform binaries built successfully
- [ ] Verify all installer packages created (DEB, RPM, DMG, MSI)
- [ ] Verify Docker image pushed to ghcr.io
- [ ] Verify all four crates published to crates.io (`rustnet-monitor`, `rustnet-core`, `rustnet-capture`, `rustnet-host`) and docs.rs built
- [ ] Review automatically extracted release notes
- [ ] Verify Homebrew formula updated at https://github.com/domcyrus/homebrew-rustnet
- [ ] Verify Chocolatey package updated at https://github.com/domcyrus/rustnet-chocolatey
- [ ] Verify FreeBSD build at https://github.com/domcyrus/rustnet-bsd
- [ ] Announce release (if applicable)

## Maintenance: New Ubuntu and Fedora Releases

This is an occasional task, not part of every release. When a new Ubuntu interim or LTS, or a new Fedora release, is published and we want RustNet packages to ship for it:

1. **Ubuntu PPA**: add the new codename to the matrix in [`.github/workflows/ppa-release.yml`](.github/workflows/ppa-release.yml) (the `set-matrix` job's `releases=[...]` list and the `workflow_dispatch` choice options). Confirm the new series ships `rustc-1.88` (or whatever the current `rust-version` floor in `Cargo.toml` is). Reference: issue [#254](https://github.com/domcyrus/rustnet/issues/254) added Ubuntu 26.04 (Resolute) support.
2. **Fedora COPR**: add the new chroot in the COPR project settings at [https://copr.fedorainfracloud.org/coprs/domcyrus/rustnet/edit/](https://copr.fedorainfracloud.org/coprs/domcyrus/rustnet/edit/). The chroot list is managed in the COPR UI, not in this repo.
3. Trigger a `workflow_dispatch` of `Release to Ubuntu PPA` for the new codename to verify the build before relying on it from the next tagged release.

Conversely, when an older Ubuntu series is no longer worth supporting (no `rustc-1.88` in archive, or end of life), remove it from the same two locations and update [INSTALL.md](INSTALL.md) and [debian/README.md](debian/README.md) to match.

## Versioning

RustNet follows [Semantic Versioning (SemVer)](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backward-compatible functionality additions
- **PATCH** version for backward-compatible bug fixes

Examples:

- `v0.1.0` → `v0.1.1` (bug fixes)
- `v0.1.1` → `v0.2.0` (new features)
- `v0.2.0` → `v1.0.0` (major changes, API stability)
