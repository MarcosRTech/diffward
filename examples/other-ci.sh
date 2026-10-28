#!/usr/bin/env sh
# Any CI (Jenkins, CircleCI, Bitbucket, Azure Pipelines, Buildkite...):
# fetch the target branch, then let diffward compare against it.
set -eu

TARGET_BRANCH="${TARGET_BRANCH:-main}"
git fetch --quiet origin "$TARGET_BRANCH"

# Single self-contained binary; pick the asset for your runner
# (linux-x64, linux-arm64, darwin-arm64, darwin-x64, windows-x64.exe).
curl -fsSL -o diffward https://github.com/MarcosRTech/diffward/releases/latest/download/diffward-linux-x64
chmod +x diffward

./diffward --diff "origin/$TARGET_BRANCH" --fail-on high --sarif diffward.sarif

# If the CI only hands you a patch file instead of a git checkout:
#   diffward --diff-file changes.patch
