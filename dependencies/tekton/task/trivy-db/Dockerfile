# dependencies/tekton/task/trivy-db/Dockerfile
#
# Builds a custom Trivy image with the vulnerability DB pre-baked.
# This eliminates the 91MB DB download on every pipeline run.
#
# The Java DB (861MB) is intentionally excluded — we only scan for OS
# and language package vulnerabilities, not JAR-level analysis.
#
# Rebuild periodically to refresh the vulnerability DB:
#   docker build -t docker.io/nkanyezisolutions/trivy-db:latest .
#   docker push docker.io/nkanyezisolutions/trivy-db:latest
#
# Recommended: rebuild weekly via a GitHub Actions workflow.

FROM docker.io/aquasec/trivy:latest

# Pre-download the vulnerability DB into /trivy-db at image build time.
# TRIVY_CACHE_DIR tells the scanner where to find the DB at runtime —
# no network calls needed during pipeline runs.
RUN trivy image --download-db-only --cache-dir /trivy-db

ENV TRIVY_CACHE_DIR=/trivy-db