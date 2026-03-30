# blanketops-environments-supply-chain

A Kubernetes operator that manages a full software supply chain pipeline from two CRs. Built with Kubebuilder, powered by Tekton.

> "Treat your pipeline as infrastructure, not a script."

---

## Overview

`blanketops-environments-supply-chain` is part of the [BlanketOps](https://github.com/ntlaletsi70) platform engineering project. It implements a supply chain security pipeline as a Kubernetes controller — declarative, auditable, and self-managing.

A `SupplyChain` CR defines the pipeline for a repository. An `ImageBuild` CR triggers an execution. The controller drives a Tekton `PipelineRun` through build, scan, sign, attest, and publish — all reconciled automatically.

```
SupplyChain (1:1 per repository — this is law)
    └── owns ──► ImageBuild (one per execution)
                     └── owns ──► Tekton PipelineRun
                                      ├── buildpacks        (build)
                                      ├── sonarqube-scanner (quality gate)
                                      ├── trivy-scanner     (vulnerability scan)
                                      ├── cosign-sign       (keyless signing)
                                      ├── tekton-chains-attest (provenance)
                                      └── grafeas-publish   (metadata)
```

---

## Architecture

### CRs

**`SupplyChain`** — the pipeline definition for a repository. One per repo, no exceptions. The controller enforces this at reconcile time. It also owns and reconciles the custom Tekton Tasks, ensuring they exist before any `ImageBuild` can proceed.

**`ImageBuild`** — a single pipeline execution. Create one manually to trigger a build. It owns the Tekton `PipelineRun` and tracks per-step status. The controller guards on `SupplyChain` being `Ready` before creating the `PipelineRun`.

### Tasks

The operator manages two categories of Tasks:

**Controller-managed (reconciled automatically):**

- `sonarqube-scanner` — static analysis quality gate
- `cosign-sign` — keyless image signing via Cosign + Fulcio + Rekor
- `tekton-chains-attest` — SLSA provenance attestation via Tekton Chains
- `grafeas-publish` — artifact metadata publishing to Grafeas

**Prerequisites (install once):**

- `git-clone` — Tekton Hub
- `buildpacks` — Tekton Hub
- `trivy-scanner` — Tekton catalog

---

## Prerequisites

### Cluster

```bash
# Tekton Pipelines
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml

# Tekton Chains
kubectl apply --filename https://storage.googleapis.com/tekton-releases/chains/latest/release.yaml
```

### Hub Tasks

```bash
# git-clone
kubectl apply -f https://raw.githubusercontent.com/tektoncd/catalog/main/task/git-clone/0.9/git-clone.yaml

# buildpacks
kubectl apply -f https://raw.githubusercontent.com/tektoncd/catalog/main/task/buildpacks/0.6/buildpacks.yaml

# trivy-scanner
kubectl apply -f https://raw.githubusercontent.com/tektoncd/catalog/main/task/trivy-scanner/0.1/trivy-scanner.yaml
```

Verify:

```bash
kubectl get tasks
```

---

## Install

```bash
git clone https://github.com/ntlaletsi70/blanketops-environments-supply-chain.git
cd blanketops-environments-supply-chain

make manifests
make install
```

Verify CRDs:

```bash
kubectl get crds | grep blanketops
```

Run the controller:

```bash
make run
```

---

## Usage

### 1. Apply a SupplyChain

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChain
metadata:
  name: my-app
  namespace: default
spec:
  repository: your-org/your-repo
  image:
    registry: ttl.sh
    name: my-app
    tagStrategy: git-sha
    builderImage: paketobuildpacks/builder-jammy-base
  steps:
    buildpacks: true
    trivy: true
    sign: true
    attest: true
    sonarQube:
      enabled: true
      serverURL: http://sonarqube.svc.cluster.local:9000
      tokenSecretRef:
        name: sonarqube-token
        key: token
    grafeas:
      enabled: true
      serverURL: http://grafeas.svc.cluster.local:8080
  signing:
    fulcioURL: https://fulcio.sigstore.dev
    rekorURL: https://rekor.sigstore.dev
  serviceAccountName: default
```

```bash
kubectl apply -f supplychain.yaml
kubectl get supplychain
```

The controller reconciles the custom Tasks and marks the `SupplyChain` `Ready`.

### 2. Trigger a Build

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: ImageBuild
metadata:
  name: my-app-build-001
  namespace: default
spec:
  supplyChainRef:
    name: my-app
  gitRef:
    url: https://github.com/your-org/your-repo
    revision: main
```

```bash
kubectl apply -f imagebuild.yaml
kubectl get imagebuild -w
```

Watch the phase move from `Pending` → `Running` → `Succeeded`.

### 3. Inspect per-step status

```bash
kubectl describe imagebuild my-app-build-001
```

### 4. Verify the signed image

```bash
cosign verify \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://oauth2.sigstore.dev/auth" \
  ttl.sh/my-app:<tag>
```

---

## Uninstall

```bash
make force-uninstall
```

---

## Group

`supplychain.blanketops.dev`

---

## Part of BlanketOps

This operator is one component of the BlanketOps platform:

- [blanketops-environments](https://github.com/ntlaletsi70) — environment orchestration
- [blanketops-environments-supply-chain](https://github.com/ntlaletsi70/blanketops-environments-supply-chain) — supply chain pipeline
- [blanketops-runners](https://github.com/ntlaletsi70) — GitHub Actions self-hosted runners

---

## Acknowledgements

- [Tekton](https://tekton.dev)
- [Cosign / Sigstore](https://sigstore.dev)
- [Cloud Native Buildpacks](https://buildpacks.io)
- [Trivy](https://aquasecurity.github.io/trivy)
- [Tekton Chains](https://tekton.dev/docs/chains)
- [Grafeas](https://grafeas.io)
- [Kubebuilder](https://book.kubebuilder.io)
