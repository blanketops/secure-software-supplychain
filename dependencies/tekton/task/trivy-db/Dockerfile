# Trivy with its vulnerability DB baked in, so a scan downloads nothing.
#
# The Java DB (about 1.3 GB) is left out. Trivy uses it only to identify .jar
# files inside an image; the trivy-scanner Task fetches it on demand when a
# scanned image contains Java, and never otherwise. Leaving it out takes the
# image from about 2.45 GB to about 1.15 GB unpacked.
#
# Rebuild periodically for a fresh DB, push with a dated tag, and pin the new
# digest in the TRIVY_IMAGE default of ../trivyscanner.yaml.
FROM docker.io/aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222

RUN trivy image --download-db-only --cache-dir /trivy-db

ENV TRIVY_CACHE_DIR=/trivy-db
