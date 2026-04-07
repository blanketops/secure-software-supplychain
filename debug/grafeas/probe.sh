#!/bin/sh
# Quick Grafeas gRPC probe via grpcurl + protos
# Usage: ./probe.sh grafeas:8080 blanketops myimage:tag
# Requires: git, wget, tar (all available in alpine)

HOST="${1:-grafeas.default.svc.cluster.local:8080}"
PROJECT="${2:-blanketops}"
IMAGE="${3:-debug/image:latest}"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

echo "=== Grafeas gRPC probe: ${HOST} ==="

echo ""
echo "--- Setup ---"
apk add --no-cache git 2>/dev/null
wget -qO /tmp/grpcurl.tar.gz \
  https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz \
  && tar -xzf /tmp/grpcurl.tar.gz -C /usr/local/bin grpcurl \
  && pass "grpcurl ready" || fail "grpcurl download failed"

[ -d /tmp/grafeas ] || git clone --quiet --depth=1 --filter=blob:none https://github.com/grafeas/grafeas.git /tmp/grafeas
pass "grafeas protos ready"
[ -d /tmp/googleapis ] || git clone --quiet --depth=1 --filter=blob:none https://github.com/googleapis/googleapis.git /tmp/googleapis
pass "googleapis protos ready"

GRPC="-plaintext -import-path /tmp/grafeas -import-path /tmp/googleapis -proto proto/v1beta1/grafeas.proto"

echo ""
echo "--- 1. Create note ---"
grpcurl $GRPC \
  -d "{\"parent\": \"projects/${PROJECT}\", \"noteId\": \"build\", \"note\": {\"shortDescription\": \"probe note\", \"kind\": \"BUILD\", \"build\": {\"builderVersion\": \"probe-v1\"}}}" \
  ${HOST} grafeas.v1beta1.GrafeasV1Beta1/CreateNote \
  && pass "Note created" || echo "[INFO] Note may already exist"

echo ""
echo "--- 2. Create occurrence ---"
grpcurl $GRPC \
  -d "{
    \"parent\": \"projects/${PROJECT}\",
    \"occurrence\": {
      \"resource\": {\"uri\": \"${IMAGE}\"},
      \"noteName\": \"projects/${PROJECT}/notes/build\",
      \"kind\": \"BUILD\",
      \"build\": {
        \"provenance\": {
          \"id\": \"probe-run\",
          \"projectId\": \"${PROJECT}\",
          \"builtArtifacts\": [{\"id\": \"${IMAGE}\", \"names\": [\"${IMAGE}\"]}]
        }
      }
    }
  }" \
  ${HOST} grafeas.v1beta1.GrafeasV1Beta1/CreateOccurrence \
  && pass "Occurrence created" || fail "Occurrence creation failed"

echo ""
echo "=== All checks passed ==="
