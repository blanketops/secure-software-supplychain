# secure-software-supply-chain

A Kubernetes operator that manages a full software supply chain pipeline from two CRs. Built with Kubebuilder, powered by Tekton, secured by Sigstore.

> "Treat your pipeline as infrastructure, not a script."

---

## Overview

`secure-software-supply-chain` is part of the [BlanketOps](https://github.com/ntlaletsi70) platform engineering project. It implements a supply chain security pipeline as a Kubernetes controller — declarative, auditable, and self-managing.

A `SupplyChain` CR defines the pipeline for a repository. An `ImageBuild` CR is auto-created on every GitHub push via a Tekton EventListener — no manual triggering required. The controller drives a Tekton `PipelineRun` through build, scan, sign, attest, and publish — all reconciled automatically.

```
GitHub Push
    └── EventListener (Tekton Triggers)
            └── creates ──► ImageBuild CR
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

**`SupplyChain`** — the pipeline definition for a repository. One per repo, no exceptions. The controller enforces this at reconcile time. It owns and reconciles:
- Custom Tekton Tasks
- TriggerBinding, TriggerTemplate, EventListener (GitHub webhook automation)
- The `supply-chain-runner` ServiceAccount (created before the EventListener deployment uses it)

**`ImageBuild`** — a single pipeline execution. Auto-created by the EventListener on every GitHub push. It owns the Tekton `PipelineRun` and tracks per-step status. The controller guards on `SupplyChain` being `Ready` before creating the `PipelineRun`.

**`ImageSignature`** — the signing audit record. Created after a successful signing context is established. Carries the Fulcio cert reference, Rekor log index, and Grafeas occurrence.

### Trigger Layer

The `SupplyChain` controller automatically provisions the full Tekton Triggers stack per chain:

- **TriggerBinding** — extracts `git-repo-url`, `git-revision`, `git-commit-sha`, `short-sha`, `repo-full-name` from the GitHub push payload
- **TriggerTemplate** — creates an `ImageBuild` CR with the extracted params. Name is deterministic: `<supplychain>-<branch>-<full-sha>` — idempotent on replay
- **EventListener** — shared across all SupplyChains in the namespace, runs as `supply-chain-runner` SA

The repo full name (`org/repo`) lives in the `blanketops.dev/repo-full-name` annotation — Kubernetes label values cannot contain `/`.

RBAC for the EventListener pod is managed in `config/rbac/eventlistener_role.yaml`.

### Mediator

The `ImageBuildReconciler` uses a mediator pattern to sequence prerequisites before pipeline construction.

**Gate 1 — Prerequisites**
- Git SSH ExternalSecret reconciliation
- Registry ExternalSecret reconciliation (Kaniko + Tekton Chains split credentials)
- SonarQube ExternalSecret reconciliation
- Convergence wait — all secrets must exist before proceeding

**Gate 2 — Signing Context (three-proof authorization)**

Before Fulcio is called, three SubjectAccessReviews are performed against the `supply-chain-runner` ServiceAccount. All three must pass:

| Proof | Resource | Verb | Meaning |
|-------|----------|------|---------|
| ScopeProof | `supplychains` | `get` | SA can access the chain definition it claims to execute against |
| IntentProof | `imagebuilds` | `create` | SA is authorized to initiate a build execution |
| OutputProof | `imagesignatures` | `create` | SA is authorized to produce signing records |

All three proofs are embedded in the attestation predicate that Fulcio signs over. This makes the ephemeral cert meaningful — it signs over a complete, API-server-verified authorization story, not just an identity claim.

After all three SARs pass, a short-lived OIDC token is minted from the ServiceAccount and exchanged with Fulcio for an ephemeral signing certificate. The private key is discarded after the pipeline completes.

**Gate 3 — PipelineRun**

Builds and creates the Tekton `PipelineRun` with the signing context injected. PipelineRun names are a SHA256-derived short hash of the `ImageBuild` name — always under 63 characters. The full `ImageBuild` name is stored in the `blanketops.dev/image-build` label for traceability.

### Tasks

**Controller-managed (reconciled automatically by `SupplyChainReconciler`):**
- `sonarqube-scanner` — static analysis quality gate
- `cosign-sign` — keyless image signing via Cosign + Fulcio + Rekor
- `tekton-chains-attest` — SLSA provenance attestation via Tekton Chains
- `grafeas-publish` — artifact metadata publishing to Grafeas

**Prerequisites (installed separately):**
- `git-clone`, `buildah`, `skopeo`, `trivy-scanner`

---

## RBAC

### Controller manager

The controller manager ClusterRole is generated from kubebuilder markers and covers: `supplychain.blanketops.dev` resources, Tekton Tasks and PipelineRuns, Tekton Triggers resources, ExternalSecrets, core resources (ServiceAccounts, Secrets), TokenRequest, and SubjectAccessReviews.

### Pipeline runner

The `supply-chain-runner` ServiceAccount requires:

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

### EventListener pod

The EventListener deployment runs as `supply-chain-runner` and requires additional permissions to watch Tekton Triggers resources:

```bash
kubectl apply -f config/rbac/eventlistener_role.yaml
```

---

## Prerequisites

### Cluster dependencies

```bash
# Tekton Pipelines
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml

# Tekton Triggers
kubectl apply --filename https://storage.googleapis.com/tekton-releases/triggers/latest/release.yaml
kubectl apply --filename https://storage.googleapis.com/tekton-releases/triggers/latest/interceptors.yaml

# Tekton Chains
kubectl apply --filename https://storage.googleapis.com/tekton-releases/chains/latest/release.yaml

# Sigstore (Fulcio + Rekor + ctlog)
# see dependencies/sigstore/

# External Secrets Operator
# see dependencies/eso/
```

---

## Install

### Deploy into cluster

```bash
# build the controller image
docker build -t blanketops/supply-chain-controller:latest .

# load into kind
kind load docker-image blanketops/supply-chain-controller:latest --name blanketops

# install CRDs
make install

# apply RBAC
kubectl apply -f config/rbac/signing_role.yaml
kubectl apply -f config/rbac/eventlistener_role.yaml

# deploy the controller
make deploy IMG=blanketops/supply-chain-controller:latest
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

> Note: `make run` runs the controller on your local machine. Cluster-internal DNS (`*.svc.cluster.local`) will not resolve from outside the cluster. Deploy the controller into the cluster with `make deploy` for full end-to-end operation.

---

## Usage

### 1. Apply a SupplyChain

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChain
metadata:
  name: for-kaniko-app
  namespace: default
spec:
  repository: ntlaletsi70/for-kaniko-app
  serviceAccountName: supply-chain-runner
  image:
    registry: docker.io
    name: nkanyezisolutions/for-kaniko-app
    tagStrategy: git-sha
    cloneSecretRef: github-ssh-credentials
    registrySecretRef: registry-credentials
  steps:
    buildpacks: true
    trivy: true
    sign: true
    attest: true
    sonarQube:
      serverURL: http://sonarqube-sonarqube.default.svc.cluster.local:9000
      tokenSecretRef: sonarqube-token
      projectKey: ntlaletsi70_for-kaniko-app
    grafeas:
      serverURL: http://grafeas.default.svc.cluster.local:8080
  signing:
    fulcioURL: http://fulcio-server.fulcio-system.svc.cluster.local
    rekorURL: http://rekor-server.rekor-system.svc.cluster.local
```

```bash
kubectl apply -f config/samples/supplychain_v1alpha1_supplychain.yaml
kubectl get supplychain
```

Once `Ready`, the controller has provisioned Tasks, TriggerBinding, TriggerTemplate, EventListener, and the `supply-chain-runner` ServiceAccount.

### 2. Wire the GitHub webhook

```bash
# terminal 1 — expose EventListener
kubectl port-forward svc/el-secure-software-supplychain-listener 8080:8080 -n default

# terminal 2 — proxy GitHub events into the cluster
smee --url https://smee.io/<your-channel> --target http://localhost:8080
```

In GitHub → your repo → Settings → Webhooks:
- Payload URL: your smee.io channel URL
- Content type: `application/json`
- Events: Push events only

### 3. Push a commit — builds fire automatically

```bash
kubectl get imagebuilds -n default -w
```

`ImageBuild` names are deterministic: `<supplychain>-<branch>-<full-sha>`

Phase transitions: `Pending` → `Running` → `Succeeded`

### 4. Manually trigger a build

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: ImageBuild
metadata:
  name: for-kaniko-app-manual-001
  namespace: default
spec:
  supplyChainRef:
    name: for-kaniko-app
  gitRef:
    url: git@github.com:ntlaletsi70/for-kaniko-app.git
    revision: main
  imageTag: manual-001
```

```bash
kubectl apply -f imagebuild.yaml
kubectl get imagebuild -w
```

### 5. Inspect status

```bash
kubectl describe imagebuild <name>
kubectl get pipelineruns
kubectl get imagesignatures
```

### 6. Observe via CLI

```bash
# supply chain dashboard
go run ./cmd/cli supplychain observe

# RBAC audit dashboard
go run ./cmd/cli supplychain observe rbac
```

### 7. Verify the signed image

```bash
cosign verify \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://kubernetes.default.svc.cluster.local" \
  docker.io/nkanyezisolutions/for-kaniko-app:<sha>
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

- [blanketops-environments-controller](https://github.com/ntlaletsi70) — environment orchestration
- [blanketops-environments-supply-chain](https://github.com/ntlaletsi70/secure-software-supply-chain) — supply chain pipeline (this repo)
- [blanketops-zenith-runners-pool](https://github.com/ntlaletsi70) — GitHub Actions self-hosted runners

---

## Acknowledgements

- [Tekton](https://tekton.dev)
- [Tekton Triggers](https://tekton.dev/docs/triggers)
- [Tekton Chains](https://tekton.dev/docs/chains)
- [Cosign / Sigstore](https://sigstore.dev)
- [Fulcio](https://github.com/sigstore/fulcio)
- [Rekor](https://github.com/sigstore/rekor)
- [Trivy](https://aquasecurity.github.io/trivy)
- [Grafeas](https://grafeas.io)
- [Kubebuilder](https://book.kubebuilder.io)
- [External Secrets Operator](https://external-secrets.io)

---

## Demo

> 🎬 Video demos are recorded using [vhs](https://github.com/charmbracelet/vhs) and auto-generated from tape scripts in [`demo/scripts/`](demo/scripts/).

| Demo | Description |
|------|-------------|
| Full Pipeline | GitHub push → ImageBuild → PipelineRun → Signed image |
| Setup | Fresh cluster setup: install deps, apply SupplyChain CR |
| Webhook Automation | GitHubWebhook CR: auto-register → push → pipeline fires |
| Signing Verification | Verify signed image with cosign + Rekor transparency log |

*Videos coming soon — see [`demo/`](demo/) for scripts and tape files.*
