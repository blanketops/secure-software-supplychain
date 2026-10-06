#!/usr/bin/env bash
# Scripted demo run for the bottom pane of demo/1-admission/screenrc.
# Not meant to be run standalone outside that layout (it calls `screen -X
# quit` at the end to stop the whole recording session, k9s pane included).
#
# It needs three images of one repository that a SupplyChain builds into:
#
#   SIGNED_TAG       built by the pipeline: signed by the build and by Chains
#   CHAINS_ONLY_TAG  signed by Tekton Chains only
#   UNSIGNED_TAG     pushed by hand, signed by nobody
#
# and the namespace admission-demo, labelled policy.sigstore.dev/include=true.
#
#   REPO=docker.io/<user>/<app> APP=<supplychain> SIGNED_TAG=... \
#   CHAINS_ONLY_TAG=... UNSIGNED_TAG=... asciinema rec ...
#
# The images are real. Their repository and the SupplyChain's name are shown
# as the placeholders this project's documentation uses; mask() is the only
# thing that changes what is displayed.
set -uo pipefail
: "${REPO:?}" "${APP:?}" "${SIGNED_TAG:?}" "${CHAINS_ONLY_TAG:?}" "${UNSIGNED_TAG:?}"

NS=admission-demo
POLICY_NS=${POLICY_NS:-default}

mask() {
  sed -e "s#${REPO#docker.io/}#your-dockerhub-user/your-app#g" -e "s#${APP}#your-app#g"
}

step() {
  echo
  echo "### $1"
  echo
  sleep 2
}

# run <pod> <tag>: try to run the image and say what admission answered, one
# line per policy that refused it.
run() {
  echo "\$ kubectl run $1 --image=${REPO}:$2" | mask
  local out
  out=$(kubectl run "$1" -n "$NS" --restart=Never --image="${REPO}:$2" 2>&1)
  if echo "$out" | grep -q created; then
    echo "  ADMITTED  pod/$1 created"
    return
  fi
  echo "  REFUSED by the admission webhook:"
  { echo "$out" | tr '\n' ' ' | sed 's/failed policy: /\n/g'; echo; } | tail -n +2 | while read -r refusal; do
    [ -n "$refusal" ] || continue
    policy=${refusal%%:*}
    reason=$(echo "$refusal" | sed -E 's/.*@sha256:[0-9a-f]+: //; s/ with issuer.*//; s/: *$//; s/ +$//' |
      sed -E 's/no matching signatures: none of the expected identities matched what was in the certificate, got subjects \[(.*)\]/signed, but only by \1/; s#spiffe://[^/]+/ns/##')
    printf '    %-34s %s\n' "$policy" "$reason"
  done | mask
}

echo "============================================================"
echo " Demo 1: only what the supply chain built may run"
echo
echo " Three images of the same repository are run in a namespace"
echo " the policy controller guards. One was built by the pipeline,"
echo " one was signed by Tekton Chains alone, one by nobody. Watch"
echo " which of them becomes a pod in the top pane."
echo "============================================================"
sleep 4

kubectl delete pod --all -n "$NS" --ignore-not-found >/dev/null 2>&1

step "the SupplyChainPolicy renders four policies; an image must pass all of them"
kubectl get supplychainpolicy "$APP" -n "$POLICY_NS" \
  -o jsonpath='{range .status.clusterImagePolicies[*]}{"  "}{@}{"\n"}{end}' | mask
echo
echo "  the first two trust the build's identity, the last two trust Tekton Chains':"
kubectl get supplychainpolicy "$APP" -n "$POLICY_NS" -o jsonpath='{"    "}{.status.signers[0].subject}{"\n"}'
kubectl get clusterimagepolicy "${POLICY_NS}-${APP}-chains" \
  -o jsonpath='{"    "}{.spec.authorities[0].keyless.identities[0].subject}{"\n"}'
sleep 5

step "1. built by the pipeline: signed by the build and by Tekton Chains"
run built-by-pipeline "$SIGNED_TAG"
sleep 4

step "2. signed by Tekton Chains only: the build's own signature is missing"
run chains-only "$CHAINS_ONLY_TAG"
sleep 5

step "3. pushed by hand: nobody signed it"
run pushed-by-hand "$UNSIGNED_TAG"
sleep 5

step "one of the three is running"
kubectl get pods -n "$NS"
sleep 3

step "demo done"
sleep 4

screen -X quit
