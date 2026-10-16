#!/usr/bin/env bash
# Refresh the files vendored from the solution repository: the sigstore
# policy-controller release the read cluster runs. The build cluster's tenant
# resources are copies of the solution's samples that are edited per tenant,
# so they are not overwritten here.
#
# usage: hack/sync-from-solution.sh [solution-dir]
#   solution-dir defaults to the repository this directory is in
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
solution=${1:-"$root/.."}
src="$solution/dependencies/sigstore/policy-controller"
dst="$root/policy/policy-controller"

[[ -d $src ]] || { echo "not found: $src" >&2; exit 1; }

cp "$src/00-namespace.yaml" "$src/release.yaml" "$dst/"
echo "policy-controller synced from $(git -C "$solution" rev-parse --short HEAD 2>/dev/null || echo "$solution")"
