#!/usr/bin/env bash
# End-to-end check in a disposable container: install the package as a user would, next to the
# real Claude Code, Codex, OpenCode, Pi, the skills CLI, and the optional analyzers, then exercise
# scan, add, guard, setup, the hooks, audit, trust, the adapters, the judge, and uninstall.
# Nothing touches the host beyond the Docker image.
#
#   scripts/e2e-docker.sh                  # pre-release: pack this checkout and test the tarball
#   scripts/e2e-docker.sh registry         # post-release: test the latest version on npm
#   scripts/e2e-docker.sh registry 0.1.0   # a specific published version
set -euo pipefail

mode="${1:-local}"
root="$(cd "$(dirname "$0")/.." && pwd)"
ctx="$root/test/e2e/docker"
package="@french-castle/skill-scanner"
image="${SKILL_SCANNER_E2E_IMAGE:-skill-scanner-e2e}"

command -v docker >/dev/null || { echo "e2e: docker is required" >&2; exit 2; }
rm -rf "$ctx/pkg" && mkdir -p "$ctx/pkg"
trap 'rm -rf "$ctx/pkg"' EXIT

case "$mode" in
  local)
    version="$(node -p "require('$root/package.json').version")"
    echo "e2e: building and packing $version from this checkout"
    (cd "$root" && bun run build >/dev/null && npm pack --silent --pack-destination "$ctx/pkg" >/dev/null)
    ;;
  registry)
    version="${2:-$(npm view "$package" version)}"
    echo "e2e: testing $package@$version from npm"
    ;;
  *)
    echo "usage: scripts/e2e-docker.sh [local|registry] [version]" >&2
    exit 2
    ;;
esac

docker build --build-arg "SKILL_SCANNER_VERSION=$version" -t "$image" "$ctx"
docker run --rm "$image"
