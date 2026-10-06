#!/usr/bin/env bash
# Scripted demo run for the bottom pane of demo/2-revoke-identity/screenrc.
# Not meant to be run standalone outside that layout (it calls `screen -X
# quit` at the end to stop the whole recording session, k9s pane included).
#
# Needs the stack installed with --signing-identity spiffe and the objects in
# setup.yaml applied.
set -uo pipefail
cd "$(dirname "$0")"

NS=demo
SC=your-app
SA=supply-chain-runner

step() {
  echo
  echo "### $1"
  echo
  sleep 2
}

proofs() {
  kubectl get supplychain "$SC" -n "$NS" -o jsonpath='{"  phase:     "}{.status.phase}{"\n  identity:  "}{.status.signingIdentity}{"\n  scope:     get supplychains        "}{.status.authorization.scope.allowed}{"\n  intent:    create imagebuilds      "}{.status.authorization.intent.allowed}{"\n  output:    create imagesignatures  "}{.status.authorization.output.allowed}{"\n"}'
}

echo "============================================================"
echo " Demo 2: no authorization, no identity, no certificate"
echo
echo " The build ServiceAccount of the '${SC}' SupplyChain gets a"
echo " SPIFFE identity, and with it a Fulcio signing certificate,"
echo " only while it passes three SubjectAccessReviews. Watch the"
echo " SupplyChain in the top pane as one permission is revoked and"
echo " given back."
echo "============================================================"
sleep 4

kubectl apply -f setup.yaml >/dev/null
for _ in $(seq 1 30); do [ "$(kubectl get supplychain "$SC" -n "$NS" -o jsonpath='{.status.phase}')" = Ready ] && break; sleep 1; done

step "the three reviews pass, so an identity is registered"
proofs
sleep 3

step "a pod running as ${SA} asks SPIRE for its identity, then Fulcio for a certificate"
./ask-fulcio.sh "$NS" "$SA"
sleep 3

step "any other ServiceAccount in the namespace has no identity..."
./ask-fulcio.sh "$NS" default
sleep 2

step "...and Fulcio does not take its Kubernetes token instead"
./ask-fulcio.sh "$NS" default kubernetes
sleep 3

step "revoke: delete the RoleBinding that grants the three permissions"
kubectl delete rolebinding your-app-signer -n "$NS"
sleep 3
proofs
sleep 3

step "the same pod, the same ServiceAccount, a moment later"
./ask-fulcio.sh "$NS" "$SA"
sleep 3

step "restore the RoleBinding"
kubectl apply -f setup.yaml | grep rolebinding
sleep 3
proofs
sleep 2

step "and the certificate is available again"
./ask-fulcio.sh "$NS" "$SA"
sleep 3

step "demo done"
sleep 4

screen -X quit
