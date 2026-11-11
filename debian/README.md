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

On Ubuntu 26.04 hosts with `amd64v3` enabled, follow the
[per-repository architecture workaround in INSTALL.md](../INSTALL.md#ubuntu-ppa-package-not-found-with-amd64v3)
after adding the PPA and before installing.

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

## Publishing the amd64v3 variant

Launchpad controls the PPA's enabled build processors separately from this
repository. Its [PPA documentation](https://ubuntu.com/docs/launchpad/user/reference/packaging/ppas/ppa/)
lists `amd64v3` as supported but not built by default. The RustNet PPA currently
enables `amd64`, `arm64`, and `armhf` only.

For Resolute, Launchpad nevertheless advertises an `amd64v3` index in
`InRelease`. While that index is empty, APT with architecture variants enabled
can hide the baseline `amd64` package. A successful source upload or baseline
build alone does not establish that installation works on these hosts.

To remove the need for the client workaround, a PPA owner must enable the
`amd64v3` processor in Launchpad's PPA settings and arrange a Resolute build
for that variant. Verify that the build succeeds and that the published
`dists/resolute/main/binary-amd64v3/Packages` index contains `Package: rustnet`.
Then test `apt update` and `apt-cache policy rustnet` on a variant-enabled
Ubuntu 26.04 host without an explicit `Architectures: amd64` override.
Do not remove the workaround merely because the processor has been enabled.

The GitHub workflow uploads source packages; it does not configure Launchpad's
processors. Changes to these docs do not enable or publish variant builds.

## Workflow

See [.github/workflows/ppa-release.yml](../.github/workflows/ppa-release.yml)

## Links

- [PPA Packages](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+packages)
- [Build Logs](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+builds)
