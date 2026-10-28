#!/usr/bin/env sh
# Any CI (Jenkins, CircleCI, Bitbucket, Azure Pipelines, Buildkite...):
# fetch the target branch, then let diffward compare against it.
set -eu

TARGET_BRANCH="${TARGET_BRANCH:-main}"
git fetch --quiet origin "$TARGET_BRANCH"

# With Node.js:  npx diffward ...
# With Bun:      bunx diffward ...
# No runtime:    download the single binary from the GitHub releases page.
npx --yes diffward --diff "origin/$TARGET_BRANCH" --fail-on high --sarif diffward.sarif

# If the CI only hands you a patch file instead of a git checkout:
#   diffward --diff-file changes.patch
