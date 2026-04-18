#!/bin/bash
# Generate a self-signed TLS cert for Tekton Results (dev/Kind only).
# For production, use cert-manager or a proper CA.

set -euo pipefail

NAMESPACE="tekton-pipelines"
SECRET_NAME="tekton-results-tls"
CERT_DIR=$(mktemp -d)

echo "Generating self-signed TLS certificate for Tekton Results..."

openssl req -x509 \
  -newkey rsa:4096 \
  -keyout "${CERT_DIR}/tls.key" \
  -out "${CERT_DIR}/tls.crt" \
  -sha256 \
  -days 365 \
  -nodes \
  -subj "/CN=tekton-results-api-service.${NAMESPACE}.svc.cluster.local" \
  -addext "subjectAltName=DNS:tekton-results-api-service.${NAMESPACE}.svc.cluster.local,DNS:tekton-results-api-service.${NAMESPACE}.svc,DNS:localhost" \
  2>/dev/null

# Ensure namespace exists
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Create or update the TLS secret
kubectl create secret tls "${SECRET_NAME}" \
  --cert="${CERT_DIR}/tls.crt" \
  --key="${CERT_DIR}/tls.key" \
  --namespace="${NAMESPACE}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "✓ TLS secret '${SECRET_NAME}' created in namespace '${NAMESPACE}'"

rm -rf "${CERT_DIR}"