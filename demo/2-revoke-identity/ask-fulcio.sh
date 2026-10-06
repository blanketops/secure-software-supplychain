#!/usr/bin/env bash
# ask-fulcio.sh <namespace> <serviceaccount> [spiffe|kubernetes]
#
# Asks for a signing certificate the way a build step would, and prints what
# happened in one line. With "spiffe" (the default) a pod running as the
# ServiceAccount asks SPIRE for its identity first; with "kubernetes" the
# ServiceAccount's own token is presented to Fulcio instead.
#
# Needs kubectl, python3 and openssl. Tokens and keys stay in a temporary
# directory that is removed on exit; nothing secret is printed.
set -uo pipefail
NS=$1 SA=$2 HOW=${3:-spiffe}
W=$(mktemp -d); chmod 700 "$W"
PF=""
trap '[ -n "$PF" ] && kill $PF 2>/dev/null; rm -rf "$W"; kubectl delete pod "ask-$SA" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1' EXIT

if [ "$HOW" = spiffe ]; then
  kubectl delete pod "ask-$SA" -n "$NS" --ignore-not-found >/dev/null 2>&1
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: ask-$SA, namespace: $NS}
spec:
  serviceAccountName: $SA
  restartPolicy: Never
  containers:
  - name: fetch
    image: ghcr.io/spiffe/spire-agent:1.15.3
    imagePullPolicy: IfNotPresent
    command: ["/opt/spire/bin/spire-agent"]
    args: ["api", "fetch", "jwt", "-audience", "sigstore", "-socketPath", "/spiffe-workload-api/spire-agent.sock"]
    volumeMounts: [{name: spiffe, mountPath: /spiffe-workload-api, readOnly: true}]
  volumes:
  - name: spiffe
    csi: {driver: csi.spiffe.io, readOnly: true}
YAML
  for _ in $(seq 1 60); do
    case "$(kubectl get pod "ask-$SA" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)" in Succeeded|Failed) break ;; esac
    sleep 1
  done
  kubectl logs "ask-$SA" -n "$NS" > "$W/out" 2>&1
  grep -o -E 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "$W/out" | head -1 > "$W/token"
  if [ ! -s "$W/token" ]; then
    echo "  SPIRE  refused $NS/$SA: $(grep -o 'desc = .*' "$W/out" | head -1 | sed 's/desc = //')"
    exit 0
  fi
else
  kubectl create token "$SA" -n "$NS" --audience sigstore --duration 10m > "$W/token"
fi

kubectl port-forward -n fulcio-system svc/fulcio-server 15557:80 >/dev/null 2>&1 & PF=$!
sleep 2
W="$W" HOW="$HOW" python3 - <<'PY'
import base64, json, os, subprocess, urllib.error, urllib.request
w, how = os.environ['W'], os.environ['HOW']
token = open(f'{w}/token').read().strip()
claims = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))
if how == 'spiffe':
    print('  SPIRE  issued an identity:', claims['sub'])
else:
    print('  token  of', claims['sub'], 'issued by', claims['iss'])
subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', f'{w}/key.pem'], check=True)
pub = subprocess.check_output(['openssl', 'ec', '-in', f'{w}/key.pem', '-pubout'], stderr=subprocess.DEVNULL).decode()
proof = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', f'{w}/key.pem'], input=claims['sub'].encode(),
                       capture_output=True, check=True).stdout
body = {'credentials': {'oidcIdentityToken': token},
        'publicKeyRequest': {'publicKey': {'algorithm': 'ECDSA', 'content': pub},
                             'proofOfPossession': base64.b64encode(proof).decode()}}
req = urllib.request.Request('http://localhost:15557/api/v2/signingCert', data=json.dumps(body).encode(),
                             headers={'Content-Type': 'application/json'})
try:
    out = json.loads(urllib.request.urlopen(req, timeout=60).read())
except urllib.error.HTTPError as e:
    print('  Fulcio refused:', json.loads(e.read()).get('message', e.code))
    raise SystemExit(0)
leaf = (out.get('signedCertificateEmbeddedSct') or out.get('signedCertificateDetachedSct'))['chain']['certificates'][0]
san = subprocess.run(['openssl', 'x509', '-noout', '-ext', 'subjectAltName'], input=leaf.encode(),
                     capture_output=True).stdout.decode().split('\n')[1].strip()
print('  Fulcio issued a signing certificate for', san.removeprefix('URI:'))
PY
