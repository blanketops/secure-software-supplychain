FROM docker.io/aquasec/trivy:latest

# Pre-bake both DBs at image build time
RUN trivy image --download-db-only --cache-dir /trivy-db && \
    trivy image --download-java-db-only --cache-dir /trivy-db

ENV TRIVY_CACHE_DIR=/trivy-db