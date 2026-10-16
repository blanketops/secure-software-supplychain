#!/usr/bin/env bash
# Refresh the files vendored from the solution repository: the sigstore
# policy-controller release the read engine runs. The build engine's tenant
# resources are copies of the solution's samples that are edited per tenant,
# so they are not overwritten here.
#
# usage: hack/sync-from-solution.sh [solution-dir]
#   solution-dir defaults to ../secure-software-supply-chain
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
solution=${1:-"$root/../secure-software-supply-chain"}
src="$solution/dependencies/sigstore/policy-controller"
dst="$root/platforms/secure-read-engine/policy-controller"

[[ -d $src ]] || { echo "not found: $src" >&2; exit 1; }

cp "$src/00-namespace.yaml" "$src/release.yaml" "$dst/"
echo "policy-controller synced from $(git -C "$solution" rev-parse --short HEAD 2>/dev/null || echo "$solution")"
