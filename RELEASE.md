# Release Process

This document is for maintainers releasing new versions of RustNet.

## Creating a New Release

### 1. Prepare the Release

Update version in Cargo.toml if needed!
Update CHANGELOG.md with release notes

```bash
# Ensure you're on the main branch with latest changes
git checkout main
git pull origin main

# Test the build
cargo build --release
cargo test
```

### 2. Commit Release Changes

```bash
# Stage and commit the version and changelog changes
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "Release v0.2.0

- Fixed process display stability issues on macOS
- Improved PKTAP header processing  
- Enhanced process name normalization
- Added comprehensive debug logging"
```

### 3. Create and Push Git Tag

```bash
# Create an annotated tag with release notes
git tag -a v0.2.0 -m "Release v0.2.0

- Fixed process display stability issues on macOS
- Improved PKTAP header processing
- Enhanced process name normalization
- Added comprehensive debug logging
"

# Push the tag to trigger GitHub release
git push origin v0.2.0
```

### 4. Create GitHub Release

1. Go to the [GitHub repository releases page](https://github.com/domcyrus/rustnet/releases)
2. Click "Create a new release"
3. Select the tag you just pushed (v0.2.0)
4. Set the release title (e.g., "RustNet v0.2.0")
5. Add release notes describing changes, fixes, and new features
6. Attach pre-built binaries if available
7. Click "Publish release"

Alternatively, use GitHub CLI:

```bash
# Install GitHub CLI if not already installed
# brew install gh

# Create release from tag
gh release create v0.2.0 \
  --title "RustNet v0.2.0" \
  --notes-file CHANGELOG.md \
  --target main
```

### 5. Update Homebrew Formula

After creating the GitHub release, update the Homebrew formula:

```bash
# Calculate SHA256 of the source tarball
curl -L "https://github.com/domcyrus/rustnet/archive/v0.2.0.tar.gz" | shasum -a 256

# The output will be something like:
# a1b2c3d4e5f6... (64-character hash)
```

Update the Homebrew formula file (`rustnet.rb` in your tap repository):

```ruby
class Rustnet < Formula
  desc "High-performance network monitoring tool with TUI"
  homepage "https://github.com/domcyrus/homebrew-rustnet"
  url "https://github.com/domcyrus/rustnet/archive/v0.2.0.tar.gz"
  sha256 "a1b2c3d4e5f6..." # Replace with actual SHA256 from above
  license "Apache-2.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system "#{bin}/rustnet", "--version"
  end
end
```

### 6. Test and Submit Homebrew Update

```bash
# Clone or update your homebrew tap repository
git clone https://github.com/domcyrus/homebrew-rustnet.git
cd homebrew-rustnet

# Update the formula file with new version and SHA256
# Edit rustnet.rb with the values from step 4

# Test the formula locally
brew install --build-from-source ./rustnet.rb
brew test rustnet
brew audit --strict rustnet.rb

# Commit and push the updated formula
git add rustnet.rb
git commit -m "Update rustnet to v0.2.0"
git push origin main
```

### 7. Verify the Release

```bash
# Test installation from Homebrew
brew uninstall rustnet
brew update
brew install domcyrus/rustnet/rustnet

# Verify the new version
rustnet --version
```

## Automated Release Workflow

For future releases, consider setting up GitHub Actions to automate parts of this process:

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags:
      - 'v*'
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build and Release
        run: |
          cargo build --release
          # Add steps to create release artifacts
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: target/release/rustnet
          generate_release_notes: true
```

## Release Checklist

Before each release, ensure:

- [ ] Version number updated in `Cargo.toml`
- [ ] `CHANGELOG.md` updated with release notes
- [ ] All tests pass (`cargo test`)
- [ ] Documentation is up to date
- [ ] Git tag created and pushed
- [ ] GitHub release created
- [ ] Homebrew formula updated with correct SHA256
- [ ] Formula tested locally
- [ ] Release announced (if applicable)

## Versioning

RustNet follows [Semantic Versioning (SemVer)](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backward-compatible functionality additions
- **PATCH** version for backward-compatible bug fixes

Examples:

- `v0.1.0` → `v0.1.1` (bug fixes)
- `v0.1.1` → `v0.2.0` (new features)
- `v0.2.0` → `v1.0.0` (major changes, API stability)
