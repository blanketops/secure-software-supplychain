#!/usr/bin/env bash
# Walks through the credentials phase of an install, one step at a time: the
# store, how it logs in to Vault, the keys it answers to, a value going into Vault, and the same value
# arriving in a Kubernetes Secret through External Secrets.
#
# Run it after `supplychain install`, against the same cluster:
#
#   hack/vault-secrets.sh            # stops before each step
#   PAUSE=0 hack/vault-secrets.sh    # runs straight through
#
# It writes one key, git/known-hosts, which holds public host keys and nothing
# secret, and removes the objects it creates to show the sync.
set -euo pipefail

SUPPLYCHAIN=${SUPPLYCHAIN:-supplychain}
STORE=secure-software-supply-chain-store
NAMESPACE=${NAMESPACE:-default}
NAME=vault-secrets-walkthrough
GIT_HOST=${GIT_HOST:-github.com}

step() {
  printf '\n\033[1m%s\033[0m\n' "$1"
  if [ "${PAUSE:-1}" != 0 ]; then read -r -p "  press enter " _; fi
}
run() { printf '  $ %s\n' "$*"; "$@"; }

cleanup() {
  kubectl delete externalsecret "$NAME" -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete secret "$NAME" -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
  rm -f "${hosts:-}"
}
trap cleanup EXIT

step "1. Vault is running and unsealed"
run kubectl get pods -n vault
run kubectl exec -n vault vault-0 -c vault -- vault status -format=json | grep -E '"(initialized|sealed)"'

step "2. The store has logged in to Vault"
run kubectl get clustersecretstore "$STORE"
run kubectl wait clustersecretstore "$STORE" --for=condition=Ready --timeout=60s

step "3. Who the store is to Vault"
if kubectl get deployment supply-chain-svid -n vault >/dev/null 2>&1; then
  echo "  A SPIFFE identity. SPIRE issued this JWT-SVID, and Vault's role accepts no other subject:"
  kubectl get secret supply-chain-vault-jwt -n vault -o jsonpath='{.data.jwt}' | base64 -d | cut -d. -f2 |
    python3 -c 'import base64, json, sys, time
p = sys.stdin.read().strip()
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
print("    subject  ", c["sub"])
print("    audience ", ", ".join(c["aud"]))
print("    issuer   ", c["iss"])
print("    expires in", int(c["exp"] - time.time()), "seconds")'
else
  echo "  The ServiceAccount vault/supply-chain-secrets, through Vault's Kubernetes auth:"
  run kubectl get clustersecretstore "$STORE" -o jsonpath='{.spec.provider.vault.auth.kubernetes}{"\n"}'
fi

step "4. The keys every build asks the store for, and which are set"
run "$SUPPLYCHAIN" secrets list

step "5. Put a value in: the git host's keys"
hosts=$(mktemp)
ssh-keyscan "$GIT_HOST" >"$hosts" 2>/dev/null
run "$SUPPLYCHAIN" secrets set "git/known-hosts=@$hosts"

step "6. Read it back from Vault"
run "$SUPPLYCHAIN" secrets get git/known-hosts

step "7. Ask the store for it, as the operator does for each build"
kubectl apply -f - <<YAML
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: $NAME
  namespace: $NAMESPACE
spec:
  refreshInterval: 1m
  secretStoreRef: { name: $STORE, kind: ClusterSecretStore }
  target: { name: $NAME }
  data:
  - secretKey: known_hosts
    remoteRef: { key: supplychain/git/known-hosts, property: value }
YAML
run kubectl wait externalsecret "$NAME" -n "$NAMESPACE" --for=condition=Ready --timeout=90s

step "8. The Secret a build would mount holds what Vault holds"
if kubectl get secret "$NAME" -n "$NAMESPACE" -o jsonpath='{.data.known_hosts}' | base64 -d | cmp -s - "$hosts"; then
  echo "  ✓ $NAMESPACE/$NAME matches Vault"
else
  echo "  ✗ $NAMESPACE/$NAME differs from Vault" >&2
  exit 1
fi

step "9. What is left to set before the first build"
run "$SUPPLYCHAIN" secrets list
cat <<TEXT

  $SUPPLYCHAIN secrets set git/ssh-privatekey=@<key file> git/ssh-config=@<file>
  $SUPPLYCHAIN secrets set registry/config=@<docker config.json>
  $SUPPLYCHAIN secrets set github/token=@<token file>
  $SUPPLYCHAIN init-sonarqube --new-password '<password>'    # sets sonarqube/token
TEXT
