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

The PPA has the `amd64v3` build processor enabled for Resolute. This is a
Launchpad setting, separate from the source-upload workflow in this repository.
Keep it enabled alongside `amd64`, `arm64`, and `armhf` so new uploads can
produce variant builds. APT on variant-enabled hosts selects the `amd64v3`
index, so a successful baseline build alone is insufficient.

Enabling a processor does not automatically build already-published sources.
To request a missing build for an existing release without a new upload:

1. Open [Copy packages](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+copy-packages)
   while signed in as the PPA owner.
2. Select the published `rustnet-monitor` source for **Resolute**.
3. Choose **This PPA**, **The same series**, and **Copy existing binaries**.
4. Submit **Copy Packages** and check the new `amd64v3` build.

**Copy existing binaries** preserves completed builds while allowing builds
for newly enabled processors. Do not select **Rebuild the copied sources**:
Launchpad rejects a source-only copy when the same version already has
published binaries in the destination archive. See the
[Launchpad PPA guide](https://launchpad-help.readthedocs.io/en/latest/how-to/distribute-ubuntu-software.html).

Before considering the installation issue resolved:

- Confirm the variant build succeeds and completes publication. A queued,
  building, or uploading status is not enough.
- Check that the published
  [variant index](https://ppa.launchpadcontent.net/domcyrus/rustnet/ubuntu/dists/resolute/main/binary-amd64v3/Packages.gz)
  contains `Package: rustnet` for the expected version.
- On an Ubuntu 26.04 host with `APT::Architecture-Variants "amd64v3";` enabled
  and no per-PPA architecture override, run `sudo apt update` and
  `apt-cache policy rustnet`. Verify that the candidate comes from the variant
  index, then test installation with `sudo apt install rustnet`.

The [installation guide](../INSTALL.md#ubuntu-ppa-package-not-found-with-amd64v3)
explains refreshing package lists and removing an earlier baseline override
once the variant is published.

## Workflow

See [.github/workflows/ppa-release.yml](../.github/workflows/ppa-release.yml)

## Links

- [PPA Packages](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+packages)
- [Build Logs](https://launchpad.net/~domcyrus/+archive/ubuntu/rustnet/+builds)
