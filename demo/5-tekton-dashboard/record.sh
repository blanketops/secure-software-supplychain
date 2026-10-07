#!/usr/bin/env bash
# Records demo 5: a real build, followed in the Tekton Dashboard.
#
#   APP=<supplychain> GIT_REPO=<org>/<repo> REVISION=<branch> \
#   MAPS="--map <real>=<placeholder> ..." demo/5-tekton-dashboard/record.sh
#
# MAPS lists every real name the dashboard would show (the SupplyChain, the
# image repository, the git repository, hostnames) and what to show instead,
# longer names first. With MAPS empty the dashboard is recorded as it is.
#
# Needs kubectl, firefox, python3 with Pillow, and the stack installed.
set -euo pipefail
: "${APP:?}" "${GIT_REPO:?}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NS=${NS:-default}
REVISION=${REVISION:-main}
MAPS=${MAPS:-}
WORK=$(mktemp -d)
BUILD=${APP}-demo

# The run as the proxy shows it: its own name, through the same replacements.
shown() {
  python3 - "$1" $MAPS <<'PY'
import sys
name, pairs = sys.argv[1], [a for a in sys.argv[2:] if a != '--map']
for pair in pairs:
    real, placeholder = pair.split('=', 1)
    name = name.replace(real, placeholder)
print(name)
PY
}

pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

kubectl port-forward -n tekton-pipelines svc/tekton-dashboard 19097:9097 >/dev/null 2>&1 &
pids+=($!)
sleep 3
# shellcheck disable=SC2086
python3 "$HERE/mask-proxy.py" --listen 18097 --upstream http://127.0.0.1:19097 $MAPS &
pids+=($!)
firefox --headless --no-remote --marionette --profile "$WORK" about:blank >/dev/null 2>&1 &
pids+=($!)

kubectl delete imagebuild "$BUILD" -n "$NS" --ignore-not-found >/dev/null
# The run of an earlier recording has the same name; it has to be gone, or it
# would be taken for this one, already finished.
for _ in $(seq 1 90); do
  kubectl get "pipelinerun/run-${BUILD}" -n "$NS" >/dev/null 2>&1 || break
  sleep 2
done
rm -rf "$HERE/frames"

kubectl apply -f - >/dev/null <<YAML
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: ImageBuild
metadata:
  name: ${BUILD}
  namespace: ${NS}
spec:
  supplyChainRef:
    name: ${APP}
  gitRef:
    url: git@github.com:${GIT_REPO}.git
    revision: ${REVISION}
  imageTag: demo
YAML

cd "$HERE"
python3 record.py --dashboard http://127.0.0.1:18097 --namespace "$NS" \
  --run "$(shown "run-${BUILD}")" --frames "$HERE/frames"
python3 make-gif.py "$HERE/frames" "$HERE/demo.gif"
