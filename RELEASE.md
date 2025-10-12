# Release Process

This document is for maintainers releasing new versions of RustNet.

## Creating a New Release

### 1. Prepare the Release

Update version in `Cargo.toml`, `rpm/rustnet.spec`, and update `CHANGELOG.md` with release notes:

```bash
# Ensure you're on the main branch with latest changes
git checkout main
git pull origin main

# Update Cargo.toml version (e.g., version = "0.3.0")
# Update rpm/rustnet.spec Version field (e.g., Version: 0.3.0)
# Update CHANGELOG.md with new version section

# Update Cargo.lock and test the build
cargo build --release
cargo test
```

### 2. Commit Release Changes

```bash
# Stage and commit the version and changelog changes
git add Cargo.toml Cargo.lock CHANGELOG.md rpm/rustnet.spec
git commit -m "Release v0.3.0

- Feature or fix summary here
- Another change here
- And more changes"
```

### 3. Create and Push Git Tag

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

### 4. Finalize the Release

Once the GitHub Actions workflow completes (~15-20 minutes):

1. Go to the [GitHub repository releases page](https://github.com/domcyrus/rustnet/releases)
2. Find the draft release for your tag (e.g., `v0.3.0`)
3. Review the automatically extracted release notes
4. Publish the release (it will be created as a draft)

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

## Release Checklist

Before pushing the tag, ensure:

- [ ] Version number updated in `Cargo.toml`
- [ ] Version number updated in `rpm/rustnet.spec` (line 5: `Version: x.y.z`)
- [ ] `Cargo.lock` updated (via `cargo build`)
- [ ] `CHANGELOG.md` updated with release notes in format `## [x.y.z] - YYYY-MM-DD`
- [ ] All tests pass (`cargo test`)
- [ ] Changes committed to main branch
- [ ] Git tag created and pushed

After GitHub Actions completes:

- [ ] Verify all platform binaries built successfully
- [ ] Verify all installer packages created (DEB, RPM, DMG, MSI)
- [ ] Review automatically extracted release notes
- [ ] Publish the draft release on GitHub
- [ ] Announce release (if applicable)

## Versioning

RustNet follows [Semantic Versioning (SemVer)](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backward-compatible functionality additions
- **PATCH** version for backward-compatible bug fixes

Examples:

- `v0.1.0` → `v0.1.1` (bug fixes)
- `v0.1.1` → `v0.2.0` (new features)
- `v0.2.0` → `v1.0.0` (major changes, API stability)
