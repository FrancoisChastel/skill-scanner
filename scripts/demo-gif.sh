#!/usr/bin/env bash
# Re-render docs/demo.gif from docs/demo.tape with VHS, entirely in Docker: nothing is installed on
# the host. The image (scripts/demo-gif.Dockerfile) is the official VHS image plus Node 22, git, jq,
# the package, and the demo skills; the container only writes docs/demo.gif.
#
#   scripts/demo-gif.sh                   # pack this checkout and record it
#   scripts/demo-gif.sh registry          # record the latest version on npm
#   scripts/demo-gif.sh registry 0.3.0    # or a specific one
set -euo pipefail

mode="${1:-local}"
root="$(cd "$(dirname "$0")/.." && pwd)"
package="@french-castle/skill-scanner"
image="${SKILL_SCANNER_DEMO_IMAGE:-skill-scanner-demo}"

command -v docker >/dev/null || { echo "demo-gif: docker is required" >&2; exit 2; }
ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
mkdir -p "$ctx/pkg"

case "$mode" in
  local)
    echo "demo-gif: building and packing this checkout"
    (cd "$root" && bun run build >/dev/null && npm pack --silent --pack-destination "$ctx/pkg" >/dev/null)
    spec="/tmp/pkg/$(basename "$(ls "$ctx"/pkg/*.tgz)")"
    ;;
  registry)
    # A resolved version, not "latest", so a cached image layer never records an older release.
    spec="$package@${2:-$(npm view "$package" version)}"
    ;;
  *)
    echo "usage: scripts/demo-gif.sh [local|registry] [version]" >&2
    exit 2
    ;;
esac

echo "demo-gif: building the image with $spec"
docker build -f "$root/scripts/demo-gif.Dockerfile" --build-arg "SKILL_SCANNER_SPEC=$spec" -t "$image" "$ctx"

# The container runs as root; hand the GIF to whoever owns the tape (a no-op on Docker Desktop).
docker run --rm -v "$root/docs:/vhs" --entrypoint sh "$image" \
  -c 'vhs demo.tape && chown "$(stat -c %u:%g demo.tape)" demo.gif'
echo "demo-gif: wrote docs/demo.gif ($(du -h "$root/docs/demo.gif" | cut -f1))"
