# Ubuntu PPA Packaging for RustNet

RustNet uses GitHub Actions to automatically build and upload packages to Ubuntu PPA.

## Release Trigger

The release workflow calls `ppa-release.yml` after a GitHub release is
published. Maintainers can also dispatch `ppa-release.yml` for one Ubuntu
series. See [RELEASE.md](../RELEASE.md) for the full release sequence.

The workflow builds and uploads source packages for these Ubuntu series:

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
- **Build processors enabled**: amd64, arm64, armhf, and amd64v3 (for Resolute); package availability depends on successful build and publication

## Publishing the amd64v3 variant

Keep the PPA's `amd64v3` build processor enabled for Resolute alongside
`amd64`, `arm64`, and `armhf`. This Launchpad setting lets variant-enabled
APT clients use the normal PPA installation commands without an architecture
override.

For an existing source missing a variant build, use
[Copy packages](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+copy-packages)
with **This PPA**, **The same series**, and **Copy existing binaries**.
A source-only rebuild copy is rejected when that version already has binaries.

A successful build must also finish publication. Check the
[variant index](https://ppa.launchpadcontent.net/domcyrus/rustnet/ubuntu/dists/resolute/main/binary-amd64v3/Packages.gz),
then verify `apt-cache policy rustnet` selects it after `sudo apt update` on
Ubuntu 26.04 with `APT::Architecture-Variants "amd64v3";` enabled.

## Workflow

See [.github/workflows/ppa-release.yml](../.github/workflows/ppa-release.yml)

## Links

- [PPA Packages](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+packages)
- [Build Logs](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+builds)
