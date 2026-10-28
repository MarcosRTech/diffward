#!/usr/bin/env sh
# Any CI (Jenkins, CircleCI, Bitbucket, Azure Pipelines, Buildkite...):
# fetch the target branch, then let diffward compare against it.
set -eu

TARGET_BRANCH="${TARGET_BRANCH:-main}"
git fetch --quiet origin "$TARGET_BRANCH"

# Installs the binary for this runner's OS/CPU into the current directory,
# verified against the release's SHA256SUMS. Pin with DIFFWARD_VERSION=v0.2.0.
curl -fsSL https://github.com/MarcosRTech/diffward/releases/latest/download/install.sh | DIFFWARD_INSTALL_DIR=. sh

./diffward --diff "origin/$TARGET_BRANCH" --fail-on high --sarif diffward.sarif

# If the CI only hands you a patch file instead of a git checkout:
#   diffward --diff-file changes.patch
