#!/usr/bin/env bash
# Register the build cluster with the Argo CD that runs in the read cluster,
# as the cluster named build-cluster that argocd/supplychain.yaml
# deploys to. Creates a ServiceAccount on the build cluster and stores its
# token in an Argo CD cluster secret in the read cluster; the token never
# goes into Git. Safe to run again.
#
# usage: hack/register-build-cluster.sh [-b build-context] [-r read-context] [-s api-server]
#   -b  build cluster context      (default: kind-blanketops)
#   -r  read cluster context       (default: kind-blanketops-read)
#   -s  build API server as the read cluster's pods reach it
#       (default: https://blanketops-control-plane:6443, the kind node on the
#       shared Docker network; the name is in the API server's certificate)
set -euo pipefail

build=kind-blanketops
read=kind-blanketops-read
server=https://blanketops-control-plane:6443
while getopts "b:r:s:" opt; do
  case $opt in
    b) build=$OPTARG ;;
    r) read=$OPTARG ;;
    s) server=$OPTARG ;;
    *) echo "usage: $0 [-b build-context] [-r read-context] [-s api-server]" >&2; exit 2 ;;
  esac
done

# Argo CD applies arbitrary manifests from Git to this cluster, so it is
# given cluster-admin, as `argocd cluster add` does. Narrow the ClusterRole if
# the build cluster's directory is ever limited to known kinds.
kubectl --context "$build" apply -f - <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-manager
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: argocd-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: argocd-manager
  namespace: kube-system
---
apiVersion: v1
kind: Secret
metadata:
  name: argocd-manager-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: argocd-manager
type: kubernetes.io/service-account-token
EOF

token=""
for _ in $(seq 1 30); do
  token=$(kubectl --context "$build" -n kube-system get secret argocd-manager-token \
    -o jsonpath='{.data.token}' | base64 -d)
  [[ -n $token ]] && break
  sleep 1
done
[[ -n $token ]] || { echo "the build cluster issued no token" >&2; exit 1; }
ca=$(kubectl --context "$build" -n kube-system get secret argocd-manager-token -o jsonpath='{.data.ca\.crt}')

config=$(jq -cn --arg token "$token" --arg ca "$ca" \
  '{bearerToken: $token, tlsClientConfig: {insecure: false, caData: $ca}}')

kubectl --context "$read" -n argocd apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: build-cluster
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: cluster
type: Opaque
stringData:
  name: build-cluster
  server: $server
  config: '$config'
EOF
echo "build-cluster registered: $server"
