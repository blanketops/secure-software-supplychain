#!/usr/bin/env bash
# Scripted demo run for the bottom pane of demo/3-evidence/screenrc.
# Not meant to be run standalone outside that layout (it calls `screen -X
# quit` at the end to stop the whole recording session, k9s pane included).
#
# It runs one real build of a SupplyChain and then reads back what the build
# left behind.
#
#   APP=<supplychain> REPO=docker.io/<user>/<app> GIT_REPO=<org>/<repo> \
#   REVISION=<branch> asciinema rec ...
#
# The build is real. The image repository, the git repository and the
# SupplyChain's name are shown as the placeholders this project's
# documentation uses; mask() is the only thing that changes what is displayed.
set -uo pipefail
: "${APP:?}" "${REPO:?}" "${GIT_REPO:?}"

NS=${NS:-default}
REVISION=${REVISION:-main}
# Named after the SupplyChain, as a push-triggered build is; displayed as
# your-app-demo.
BUILD=${APP}-demo
RUN=run-${BUILD}

mask() {
  sed -e "s#${REPO#docker.io/}#your-dockerhub-user/your-app#g" -e "s#${GIT_REPO}#your-org/your-app#g" \
    -e "s#${APP}#your-app#g"
}

step() {
  echo
  echo "### $1"
  echo
  sleep 2
}

echo "============================================================"
echo " Demo 3: what a build leaves behind"
echo
echo " One build, from source to a signed image, and then the"
echo " evidence for it: who signed, with which key, and where the"
echo " transparency log recorded it. Nothing shown at the end is"
echo " what the controller assumes; it is read back from the"
echo " registry and from Rekor."
echo "============================================================"
sleep 4

kubectl delete imagebuild "$BUILD" -n "$NS" --ignore-not-found >/dev/null 2>&1
sleep 2

step "start a build"
manifest=$(cat <<YAML
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
)
echo "$manifest" | mask
echo "$manifest" | kubectl apply -f - | mask
sleep 2

step "the pipeline: nine steps, each a pod (top pane)"
# The steps run one after another, so each is reported as it finishes, in the
# pipeline's own order.
for _ in $(seq 1 30); do
  steps=$(kubectl get pipelinerun "$RUN" -n "$NS" -o jsonpath='{.spec.pipelineSpec.tasks[*].name}' 2>/dev/null)
  [ -n "$steps" ] && break
  [ "$(kubectl get imagebuild "$BUILD" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)" = Failed ] && break
  sleep 2
done
state=""
for task in $steps; do
  for _ in $(seq 1 300); do
    reason=$(kubectl get taskrun -n "$NS" -l "tekton.dev/pipelineRun=${RUN},tekton.dev/pipelineTask=${task}" \
      -o jsonpath='{.items[0].status.conditions[0].reason}' 2>/dev/null)
    case "$reason" in Succeeded|Failed|TaskRunTimeout|TaskRunCancelled) break ;; esac
    state=$(kubectl get pipelinerun "$RUN" -n "$NS" -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)
    [ "$state" = False ] && break 2
    sleep 2
  done
  printf '  %-28s %s\n' "$task" "$reason"
done
for _ in $(seq 1 60); do
  state=$(kubectl get pipelinerun "$RUN" -n "$NS" -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)
  [ "$state" = True ] || [ "$state" = False ] && break
  sleep 2
done
if [ "$state" != True ]; then
  echo "  the build did not succeed; nothing to show"
  sleep 5
  screen -X quit
  exit 1
fi
sleep 2

step "the last step verified the published image the way admission will"
kubectl logs -n "$NS" "${RUN}-verify-image-policy-pod" -c step-report 2>/dev/null | mask
sleep 5

step "ImageSignature: the build's own signature, read back from the registry and Rekor"
for _ in $(seq 1 30); do
  [ "$(kubectl get imagesignature "$BUILD" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)" = Signed ] && break
  sleep 2
done
kubectl get imagesignature "$BUILD" -n "$NS" \
  -o jsonpath='{"  phase:      "}{.status.phase}{"\n  signer:     "}{.status.subject}{"\n  key:        "}{.status.keyFingerprint}{"\n  rekor index:"}{" "}{.status.rekorLogIndex}{"\n  logged at:  "}{.status.signedAt}{"\n"}'
index=$(kubectl get imagesignature "$BUILD" -n "$NS" -o jsonpath='{.status.rekorLogIndex}')
sleep 3
echo
echo "  what cosign printed when it signed, inside the build:"
kubectl logs -n "$NS" "${RUN}-sign-image-cosign-pod" -c step-sign 2>/dev/null | grep 'tlog entry' | sed 's/^/    /'
echo
echo "  and the entry Rekor holds at index ${index}:"
kubectl port-forward -n rekor-system svc/rekor-server 13001:80 >/dev/null 2>&1 &
PF=$!
sleep 2
curl -s "http://localhost:13001/api/v1/log/entries?logIndex=${index}" | python3 -c '
import base64, datetime, json, sys
entry = list(json.load(sys.stdin).values())[0]
body = json.loads(base64.b64decode(entry["body"]))
when = datetime.datetime.fromtimestamp(entry["integratedTime"], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
print("    kind %s, index %d, integrated %s" % (body["kind"], entry["logIndex"], when))'
kill $PF 2>/dev/null
sleep 5

step "ImageBuildResult: everything that vouches for the image"
echo "  (waiting for Tekton Chains to sign the finished run and add its provenance)"
for _ in $(seq 1 60); do
  [ "$(kubectl get imagebuildresult "$BUILD" -n "$NS" -o jsonpath='{.status.evidence.complete}' 2>/dev/null)" = true ] && break
  sleep 3
done
kubectl get imagebuildresult "$BUILD" -n "$NS" -o json | python3 -c '
import json, sys
evidence = json.load(sys.stdin)["status"].get("evidence") or {}
print()
print("  %-6s %-12s %-7s %-22s %s" % ("REKOR", "KIND", "BY", "KEY", "WHAT"))
for s in evidence.get("signatures", []):
    what = s.get("predicateType", "") or "the image"
    print("  %-6s %-12s %-7s %-22s %s" % (s.get("rekorLogIndex"), s["kind"], s["signedBy"], s.get("keyFingerprint", "")[:21] + "…", what))
anchors = evidence.get("trustAnchors") or {}
print()
print("  complete:   ", evidence.get("complete"))
print("  rekor key:  ", anchors.get("rekorKey"))
print("  fulcio root:", anchors.get("fulcioRoot"))'
sleep 6

step "the same record in Tekton, as a CustomRun"
for _ in $(seq 1 20); do
  kubectl get customrun "${RUN}-result" -n "$NS" >/dev/null 2>&1 && break
  sleep 2
done
kubectl get customrun "${RUN}-result" -n "$NS" \
  -o jsonpath='{range .status.results[*]}{.name}{"="}{.value}{"\n"}{end}' |
  grep -E '^(PHASE|IMAGE_URL|POLICY_VERIFICATION|TRIVY_SCAN_SUMMARY|SIGNATURES|EVIDENCE_COMPLETE)=' |
  sed -E 's/^([A-Z_]+)=/  \1: /; s/, /\n               /g' | mask
sleep 5

step "demo done"
sleep 4

screen -X quit
