# Ubuntu PPA Packaging for RustNet

RustNet uses GitHub Actions to automatically build and upload packages to Ubuntu PPA.

## Quick Start

Push a git tag to trigger automatic PPA release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This automatically builds and uploads source packages for all supported Ubuntu series:

- Ubuntu 22.04 LTS (Jammy Jellyfish)
- Ubuntu 24.04 LTS (Noble Numbat)
- Ubuntu 26.04 LTS (Resolute Raccoon)

Each series ships versioned `rustc`/`cargo` packages satisfying the Rust 1.88 minimum required for the let-chains feature used by the project (see `rust-version` in `Cargo.toml`). The workflow pins the toolchain per series (Jammy: 1.89, Noble: 1.89, Resolute: 1.91).

## GitHub Secrets Setup

Add these secrets to your GitHub repository (Settings → Secrets and variables → Actions):

### 1. GPG_PRIVATE_KEY

Your passphrase-free CI GPG private key:

```bash
cat ci-signing-key.asc
# Copy the entire output including BEGIN/END markers
```

### 2. GPG_KEY_ID

Your CI GPG key ID:

```bash
gpg --list-keys cadetg@gmail.com
# Copy the key ID (long hex string)
```

## Installation (for users)

```bash
sudo add-apt-repository ppa:domcyrus/rustnet
sudo apt update
sudo apt install rustnet
```

## Package Details

- **Source**: rustnet-monitor
- **Binary**: rustnet
- **Maintainer**: Marco Cadetg <cadetg@gmail.com>
- **PPA**: https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet
- **Supported**: Ubuntu 22.04 LTS (Jammy), 24.04 LTS (Noble) and 26.04 LTS (Resolute)
- **Architectures**: amd64, arm64, armhf

## Workflow

See [.github/workflows/ppa-release.yml](../.github/workflows/ppa-release.yml)

## Links

- [PPA Packages](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+packages)
- [Build Logs](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+builds)
