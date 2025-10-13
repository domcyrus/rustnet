# GitHub Actions PPA Setup

## Add GitHub Secrets

Go to: **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

### 1. GPG_PRIVATE_KEY

```bash
# Display your CI private key
cat ci-signing-key.asc
```

Copy the entire output (including `-----BEGIN PGP PRIVATE KEY BLOCK-----` and `-----END...`)

- Name: `GPG_PRIVATE_KEY`
- Value: [paste the entire key]

### 2. GPG_KEY_ID

```bash
# Get your key ID
gpg --list-keys cadetg@gmail.com
```

Copy the long hex string (e.g., `ABC123...`)

- Name: `GPG_KEY_ID`
- Value: [paste just the key ID]

## Test the Workflow

```bash
# Create and push a test tag
git tag v0.14.0-test
git push origin v0.14.0-test
```

Check: **Actions** tab in GitHub → **Release to Ubuntu PPA**

## Remove Test Tag (if needed)

```bash
git tag -d v0.14.0-test
git push origin :refs/tags/v0.14.0-test
```

## Done!

From now on, just push version tags and GitHub will handle the PPA release automatically! 🚀
