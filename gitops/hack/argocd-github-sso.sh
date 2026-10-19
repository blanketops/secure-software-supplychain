#!/usr/bin/env bash
# Sign in to the read cluster's Argo CD with GitHub, through the Dex that ships
# with Argo CD. Only members of one team of the GitHub organisation can sign
# in, and they get role:admin; nobody else gets any access. The local admin
# account stays as a break-glass login. Safe to run again.
#
# Why a team: with an organisation listed, Dex's GitHub connector checks
# membership but puts only "<org>:<team>" names in the groups claim, never the
# organisation itself, so an organisation without teams signs people in with
# no groups, and therefore no permissions.
#
# Needs a GitHub OAuth App (github.com/organizations/<org>/settings/applications/new;
# an OAuth App, not a GitHub App, whose callback URLs must match exactly):
#   Homepage URL:               the Argo CD URL below
#   Authorization callback URL: <Argo CD URL>/api/dex/callback
# and the team (gh api orgs/<org>/teams -X POST -f name=<team> -f privacy=closed).
# The client secret is read from a hidden prompt (or stdin), never from the
# command line, and stored only in the argocd-secret Secret.
#
# usage: hack/argocd-github-sso.sh -i <client-id> [-k] [-o org] [-t team] [-u argocd-url] [-r read-context]
#   -k  keep the client secret already stored, instead of asking for it
set -euo pipefail

org=blanketops
team=argocd-admins
url=https://pop-os.tailf8145.ts.net:8081
read=kind-software-eng-read
client_id=""
keep=false
usage="usage: $0 -i <client-id> [-k] [-o org] [-t team] [-u argocd-url] [-r read-context]"
while getopts "i:ko:t:u:r:" opt; do
  case $opt in
    i) client_id=$OPTARG ;;
    k) keep=true ;;
    o) org=$OPTARG ;;
    t) team=$OPTARG ;;
    u) url=$OPTARG ;;
    r) read=$OPTARG ;;
    *) echo "$usage" >&2; exit 2 ;;
  esac
done
[[ -n $client_id ]] || { echo "the OAuth App's client ID is required (-i)" >&2; exit 2; }
k() { kubectl --context "$read" -n argocd "$@"; }

if $keep; then
  k get secret argocd-secret -o json | jq -e '.data["dex.github.clientSecret"]' >/dev/null \
    || { echo "no client secret stored yet; run without -k" >&2; exit 2; }
else
  if [[ -t 0 ]]; then
    read -rsp "GitHub OAuth App client secret (hidden): " secret; echo
  else
    read -r secret
  fi
  [[ -n $secret ]] || { echo "no client secret given" >&2; exit 2; }
  # The secret goes into argocd-secret; argocd-cm refers to it as $dex.github.clientSecret.
  k patch secret argocd-secret --type merge \
    -p "$(jq -cn --arg s "$secret" '{stringData: {"dex.github.clientSecret": $s}}')" >/dev/null
  unset secret
fi

dex=$(cat <<EOF
connectors:
- type: github
  id: github
  name: GitHub
  config:
    clientID: $client_id
    clientSecret: \$dex.github.clientSecret
    orgs:
    - name: $org
      teams:
      - $team
EOF
)
k patch configmap argocd-cm --type merge \
  -p "$(jq -cn --arg url "$url" --arg dex "$dex" '{data: {url: $url, "dex.config": $dex}}')" >/dev/null

# The team is admin; anyone else who somehow signs in gets nothing.
k patch configmap argocd-rbac-cm --type merge \
  -p "$(jq -cn --arg g "$org:$team" '{data: {"policy.default": "", "policy.csv": ("g, " + $g + ", role:admin\n"), scopes: "[groups]"}}')" >/dev/null

k scale deployment argocd-dex-server --replicas=1 >/dev/null
k rollout status deployment argocd-dex-server --timeout=600s
k rollout restart deployment argocd-server >/dev/null
k rollout status deployment argocd-server --timeout=300s

# Dex answers under Argo CD's URL once both are up.
for _ in $(seq 1 30); do
  if curl -sf --max-time 10 "$url/api/dex/.well-known/openid-configuration" >/dev/null; then
    echo "GitHub sign-in is ready at $url (\"Log in via GitHub\"); members of $org/$team are admins"
    exit 0
  fi
  sleep 5
done
echo "Dex did not answer at $url/api/dex; check: kubectl --context $read -n argocd logs deploy/argocd-dex-server" >&2
exit 1
