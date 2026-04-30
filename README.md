# secure-software-supply-chain

A Kubernetes operator that manages a full software supply chain pipeline from two CRs. Built with Kubebuilder, powered by Tekton, secured by Sigstore.

> "Treat your pipeline as infrastructure, not a script."

---

## Overview

`secure-software-supply-chain` is part of the [BlanketOps](https://github.com/ntlaletsi70) platform engineering project. It implements a supply chain security pipeline as a Kubernetes controller — declarative, auditable, and self-managing.

A `SupplyChain` CR defines the pipeline for a repository. An `ImageBuild` CR triggers an execution. The controller drives a Tekton `PipelineRun` through build, scan, sign, attest, and publish — all reconciled automatically.

```
SupplyChain (1:1 per repository — this is law)
    └── owns ──► ImageBuild (one per execution)
                     └── owns ──► Tekton PipelineRun
                                      ├── git-clone             (source)
                                      ├── sonarqube-scanner     (quality gate)
                                      ├── buildah               (build)
                                      ├── skopeo                (image copy)
                                      ├── trivy-scanner         (vulnerability scan)
                                      ├── cosign-sign           (keyless signing)
                                      ├── tekton-chains-attest  (provenance)
                                      └── grafeas-publish       (metadata)
```

---

## Architecture

### CRs

**`SupplyChain`** — the pipeline definition for a repository. One per repo, no exceptions. The controller enforces this at reconcile time. It owns and reconciles the custom Tekton Tasks, ensuring they exist before any `ImageBuild` can proceed.

**`ImageBuild`** — a single pipeline execution. Create one to trigger a build. It owns the Tekton `PipelineRun` and tracks per-step status. The controller guards on `SupplyChain` being `Ready` before creating the `PipelineRun`.

**`ImageSignature`** — the signing audit record. Created after a successful signing context is established. Carries the Fulcio cert reference, Rekor log index, and Grafeas occurrence.

### Mediator

The controller uses a mediator pattern to sequence prerequisites before pipeline construction. The mediator owns three phases:

**Phase 1 — Prerequisites**
- Git SSH ExternalSecret reconciliation
- Registry ExternalSecret reconciliation (Kaniko + Tekton Chains split credentials)
- SonarQube ExternalSecret reconciliation
- ServiceAccount creation with secret bindings

**Phase 2 — Signing Context (three-proof authorization)**

Before Fulcio is called, three SubjectAccessReviews are performed against the `supply-chain-runner` ServiceAccount. All three must pass:

| Proof | Resource | Verb | Meaning |
|-------|----------|------|---------|
| Scope | `supplychains` | `get` | SA can access the chain definition it claims to execute against |
| Intent | `imagebuilds` | `create` | SA is authorized to initiate a build execution |
| Output | `imagesignatures` | `create` | SA is authorized to produce signing records |

All three proofs are embedded in the attestation predicate that Fulcio signs over. This makes the ephemeral cert meaningful — it signs over a complete, API-server-verified authorization story at the chain level, not just an identity claim.

After all three SARs pass, a short-lived OIDC token is minted from the ServiceAccount and exchanged with Fulcio for an ephemeral signing certificate. The private key is discarded after the pipeline completes.

**Phase 3 — PipelineRun**
- Builds and creates the Tekton `PipelineRun` with the signing context injected

### Tasks

The operator manages two categories of Tasks:

**Controller-managed (reconciled automatically):**
- `sonarqube-scanner` — static analysis quality gate
- `cosign-sign` — keyless image signing via Cosign + Fulcio + Rekor
- `tekton-chains-attest` — SLSA provenance attestation via Tekton Chains
- `grafeas-publish` — artifact metadata publishing to Grafeas

**Prerequisites (installed via CLI or manually):**
- `git-clone`, `buildah`, `skopeo`, `trivy-scanner`

---

## RBAC

The `supply-chain-runner` ServiceAccount requires the following ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: blanketops-image-signer
rules:
- apiGroups: ["supplychain.blanketops.dev"]
  resources: ["supplychains"]
  verbs: ["get"]
- apiGroups: ["supplychain.blanketops.dev"]
  resources: ["imagebuilds"]
  verbs: ["create"]
- apiGroups: ["supplychain.blanketops.dev"]
  resources: ["imagesignatures"]
  verbs: ["create"]
```

Apply:

```bash
kubectl apply -f config/rbac/signing_role.yaml
```

---

## Prerequisites

### Cluster dependencies

Install via the CLI:

```bash
go run ./cmd/cli install
```

Or manually:

```bash
# Tekton Pipelines
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml

# Tekton Chains
kubectl apply --filename https://storage.googleapis.com/tekton-releases/chains/latest/release.yaml

# Tekton Dashboard
kubectl apply --filename https://storage.googleapis.com/tekton-releases/dashboard/latest/release.yaml

# Sigstore (Fulcio + Rekor + ctlog)
# see dependencies/sigstore/
```

---

## Install

### Build and deploy into cluster

```bash
# build the controller image
docker build -t blanketops/supply-chain-controller:dev .

# load into kind — no registry auth required
kind load docker-image blanketops/supply-chain-controller:dev

# install CRDs
make install

# apply RBAC
kubectl apply -f config/rbac/signing_role.yaml

# deploy the controller
make deploy IMG=blanketops/supply-chain-controller:dev
```

Verify:

```bash
kubectl get pods -n secure-software-supply-chain-system
kubectl get crds | grep blanketops
```

### Local development (out-of-cluster)

```bash
make install
make run
```

> Note: `make run` runs the controller on your local machine. Cluster-internal service DNS (`*.svc.cluster.local`) will not resolve. Use `kubectl port-forward` for in-cluster services like Fulcio during local development.

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
  serviceAccountName: supply-chain-runner
  image:
    registry: ttl.sh
    name: my-app
    tagStrategy: git-sha
    cloneSecretRef: github-ssh-credentials
    registrySecretRef: registry-credentials
  steps:
    sonarQube:
      enabled: true
      serverURL: http://sonarqube.sonarqube.svc.cluster.local:9000
      tokenSecretRef: sonarqube-token
    grafeas:
      enabled: true
      serverURL: http://grafeas.grafeas.svc.cluster.local:8080
  signing:
    fulcioURL: http://fulcio-server.fulcio-system.svc.cluster.local
    rekorURL: http://rekor-server.rekor-system.svc.cluster.local
```

```bash
kubectl apply -f supplychain.yaml
kubectl get supplychain
```

### 2. Trigger a build

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
    url: git@github.com:your-org/your-repo.git
    revision: main
```

```bash
kubectl apply -f imagebuild.yaml
kubectl get imagebuild -w
```

Watch the phase: `Pending` → `Running` → `Succeeded`

### 3. Inspect status

```bash
kubectl describe imagebuild my-app-build-001
kubectl get pipelineruns
kubectl get imagesignatures
```

### 4. Observe via CLI

```bash
# supply chain dashboard
go run ./cmd/cli observe

# RBAC audit dashboard
go run ./cmd/cli observe rbac
```

### 5. Verify the signed image

```bash
cosign verify \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://oauth2.sigstore.dev/auth" \
  ttl.sh/my-app:<tag>
```

---

## Uninstall

```bash
make undeploy
make uninstall
```

---

## API Group

`supplychain.blanketops.dev/v1alpha1`

**Resources:** `SupplyChain`, `ImageBuild`, `ImageSignature`, `ImageBuildResult`

---

## Part of BlanketOps

This operator is one component of the BlanketOps platform:

- [blanketops-environments](https://github.com/ntlaletsi70) — environment orchestration
- [secure-software-supply-chain](https://github.com/ntlaletsi70/secure-software-supply-chain) — supply chain pipeline (this repo)
- [blanketops-runners](https://github.com/ntlaletsi70) — GitHub Actions self-hosted runners

---

## Acknowledgements

- [Tekton](https://tekton.dev)
- [Cosign / Sigstore](https://sigstore.dev)
- [Fulcio](https://github.com/sigstore/fulcio)
- [Rekor](https://github.com/sigstore/rekor)
- [Trivy](https://aquasecurity.github.io/trivy)
- [Tekton Chains](https://tekton.dev/docs/chains)
- [Grafeas](https://grafeas.io)
- [Kubebuilder](https://book.kubebuilder.io)
- [External Secrets Operator](https://external-secrets.io)