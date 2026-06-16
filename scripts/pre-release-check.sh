#!/usr/bin/env bash
# Pre-release validation script for RustNet.
# Run this before tagging a release to catch common issues.
#
# Usage: ./scripts/pre-release-check.sh [version]
#   e.g.: ./scripts/pre-release-check.sh 1.2.0

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo -e "  ${YELLOW}!${NC} $1"; WARNINGS=$((WARNINGS + 1)); }

VERSION="${1:-}"

echo "RustNet Pre-Release Checks"
echo "=========================="
echo

# --- Version consistency ---
echo "Version consistency:"

# Read the binary's [package] version, NOT the [workspace.package] version.
# Since the workspace split, Cargo.toml has two `version =` lines and the
# workspace one (0.x libraries) comes first, so `grep '^version' | head -1`
# would read the wrong value. Anchor on the [package] section instead.
CARGO_VERSION=$(awk -F'"' '/^\[package\]/{p=1} p && /^version = /{print $2; exit}' Cargo.toml)
RPM_VERSION=$(grep '^Version:' rpm/rustnet.spec | awk '{print $2}')

if [ -n "$VERSION" ]; then
  if [ "$CARGO_VERSION" = "$VERSION" ]; then
    pass "Cargo.toml version: $CARGO_VERSION"
  else
    fail "Cargo.toml version is $CARGO_VERSION, expected $VERSION"
  fi
  if [ "$RPM_VERSION" = "$VERSION" ]; then
    pass "rpm/rustnet.spec version: $RPM_VERSION"
  else
    fail "rpm/rustnet.spec version is $RPM_VERSION, expected $VERSION"
  fi
else
  if [ "$CARGO_VERSION" = "$RPM_VERSION" ]; then
    pass "Versions match: Cargo.toml=$CARGO_VERSION, rustnet.spec=$RPM_VERSION"
  else
    fail "Version mismatch: Cargo.toml=$CARGO_VERSION, rustnet.spec=$RPM_VERSION"
  fi
  VERSION="$CARGO_VERSION"
fi

echo

# --- Changelog ---
echo "Changelog:"

if grep -q "## \[$VERSION\]" CHANGELOG.md; then
  pass "CHANGELOG.md has entry for $VERSION"
else
  fail "CHANGELOG.md missing entry for [$VERSION]"
fi

if grep -q "\[$VERSION\]: https://github.com" CHANGELOG.md; then
  pass "CHANGELOG.md has comparison link for $VERSION"
else
  fail "CHANGELOG.md missing comparison link for $VERSION"
fi

UNRELEASED_CONTENT=$(awk '/^## \[Unreleased\]/{found=1; next} /^## \[/{found=0} found{print}' CHANGELOG.md | grep -v '^$' | head -1 || true)
if [ -z "$UNRELEASED_CONTENT" ]; then
  pass "[Unreleased] section is empty (content moved to $VERSION)"
else
  warn "[Unreleased] section still has content"
fi

echo

# --- Build checks ---
echo "Build checks:"

if cargo fmt --check > /dev/null 2>&1; then
  pass "cargo fmt"
else
  fail "cargo fmt --check has formatting issues"
fi

if cargo clippy -- -D warnings > /dev/null 2>&1; then
  pass "cargo clippy"
else
  fail "cargo clippy has warnings"
fi

if cargo test > /dev/null 2>&1; then
  pass "cargo test"
else
  fail "cargo test failed"
fi

echo

# --- Dockerfile ---
echo "Dockerfile:"

CARGO_BENCHES=$(grep -c '^\[\[bench\]\]' Cargo.toml || true)
if [ "$CARGO_BENCHES" -gt 0 ]; then
  if grep -q 'COPY benches' Dockerfile; then
    pass "Dockerfile copies benches/ directory"
  else
    fail "Cargo.toml defines $CARGO_BENCHES bench(es) but Dockerfile doesn't COPY benches/"
  fi
fi

# Check that all include_bytes!()/include_str!() assets referenced at compile
# time are present in the Dockerfile's COPY commands. Since the workspace split,
# the baked-in assets (oui.gz, services) live under crates/rustnet-core/, not
# src/, and the include path is relative to the file doing the include — so scan
# both trees and resolve each path against its own source file's directory.
ROOT=$(pwd)
while IFS= read -r match; do
  [ -z "$match" ] && continue
  srcfile=${match%%:*}                       # path before the first ':'
  asset=$(printf '%s\n' "$match" | sed -E 's/.*include_(bytes|str)!\("//; s/"\).*//')
  srcdir=$(dirname "$srcfile")
  # Resolve the include path (relative to srcfile) into a repo-root-relative path
  # (portable, no GNU realpath needed).
  resolved=$(cd "$srcdir" && python3 -c "import os.path,sys; print(os.path.relpath(os.path.abspath(sys.argv[1]), sys.argv[2]))" "$asset" "$ROOT" 2>/dev/null || echo "$asset")
  if grep -q "$resolved\|$(basename "$resolved")" Dockerfile; then
    pass "Dockerfile includes compile-time asset: $resolved"
  else
    fail "Compile-time asset $resolved not found in Dockerfile COPY commands"
  fi
done < <(grep -rno -E 'include_(bytes|str)!\("[^"]*"\)' src/ crates/*/src 2>/dev/null | sort -u || true)

if docker info > /dev/null 2>&1; then
  echo
  echo "Docker build test:"
  if docker build -t rustnet:pre-release-test . > /dev/null 2>&1; then
    pass "Docker image builds successfully"
    docker rmi rustnet:pre-release-test > /dev/null 2>&1 || true
  else
    fail "Docker build failed"
  fi
else
  warn "Docker not available, skipping Docker build test"
fi

echo

# --- Git status ---
echo "Git status:"

if git diff --quiet Cargo.lock; then
  pass "Cargo.lock is up to date"
else
  fail "Cargo.lock has uncommitted changes (run cargo build)"
fi

if [ -z "$(git status --porcelain -- src/ Cargo.toml Cargo.lock CHANGELOG.md rpm/)" ]; then
  pass "No uncommitted changes in release files"
else
  warn "Uncommitted changes in release files"
fi

echo
echo "=========================="
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}$ERRORS error(s)${NC}, $WARNINGS warning(s) — fix errors before releasing"
  exit 1
elif [ "$WARNINGS" -gt 0 ]; then
  echo -e "${GREEN}0 errors${NC}, ${YELLOW}$WARNINGS warning(s)${NC} — review warnings before releasing"
else
  echo -e "${GREEN}All checks passed!${NC} Ready to tag v$VERSION"
fi
