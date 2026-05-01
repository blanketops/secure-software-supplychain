# Tekton, Shipwright, Cosign, and Buildpacks: Building a Software Supply Chain Operator on Kubernetes

Neo Tlaletsi
~8 min read · 2026

---

> "Tekton, Cosign, and Buildpacks are instrumental in building a secure, auditable software supply chain — by treating your pipeline as a Kubernetes controller."

> "Tekton, Cosign, and Buildpacks: These tools enable a fully automated supply chain security pipeline on Kubernetes. With Buildpacks, you build OCI-compliant images without managing Dockerfiles. Cosign and Sigstore handle keyless image signing against the public Fulcio and Rekor infrastructure. Tekton orchestrates the entire pipeline as a PipelineRun, while Tekton Chains generates provenance attestations. Together, they allow teams to ship signed, scanned, and attested artifacts — all driven from two Kubernetes CRs."

> "[Your personal context here — why did you build this? What problem were you solving at the time?]"

> "[Your approach summary — one paragraph. What does the operator do, at a high level?]"

> "To proceed, we will use a remote repository containing all the necessary files. The architecture of our approach is illustrated in the diagram above, showcasing how these tools work together to achieve a secure, declarative software supply chain."

---

_[INSERT ARCHITECTURE DIAGRAM HERE]_

**Figure 1:** BlanketOps Environments Supply Chain — Git source flows through a `SupplyChain` CR and `ImageBuild` CR into a Tekton PipelineRun. The left column handles build and scan (Buildpacks, SonarQube, Trivy). The right column handles signing, attestation, and metadata publishing (Cosign + Fulcio + Rekor, Tekton Chains, Grafeas). The output is a signed, attested OCI image in the registry.

---

## Overview of the Approach

This setup will demonstrate the following tools:

- [**Tekton Pipelines**](https://tekton.dev/): Orchestrates the supply chain as a Kubernetes-native PipelineRun, with each tool running as an ephemeral TaskRun.
- [**Shipwright**](https://shipwright.io/): A framework for building container images on Kubernetes, providing a consistent API across build strategies.
- [**Cloud Native Buildpacks**](https://buildpacks.io/): Builds OCI-compliant container images from source without requiring a Dockerfile (unless you really have to).
- [**SonarQube**](https://www.sonarsource.com/products/sonarqube/): Performs static code analysis as a quality gate before the image is pushed.
- [**Trivy**](https://aquasecurity.github.io/trivy/): Scans the built image for known vulnerabilities. Configured to fail the pipeline on HIGH and CRITICAL findings.
- [**Cosign**](https://github.com/sigstore/cosign) + [**Fulcio**](https://github.com/sigstore/fulcio) + [**Rekor**](https://github.com/sigstore/rekor): Signs the image using keyless signing via the public Sigstore infrastructure. No key management required — Fulcio issues a short-lived certificate and Rekor records the signature to a public transparency log.
- [**Tekton Chains**](https://tekton.dev/docs/chains/): Generates a SLSA provenance attestation for each build, recording what was built, from what source, and by what pipeline.
- [**Grafeas**](https://grafeas.io/): Publishes artifact metadata and occurrence records for every successful build.
- **SupplyChain CR:** The pipeline definition for a repository. One SupplyChain per repository — this is law.
- **ImageBuild CR:** A single pipeline execution. Create one to trigger a build.

"By the end of this guide, Kubernetes will function as the central hub for managing your software supply chain. The following step-by-step guide outlines the process for achieving this workflow."

---

## Install Prerequisites

Ensure the following tools are installed:

- **kubectl:** Command-line tool for managing Kubernetes clusters.
- **kubebuilder:** Scaffolds the operator project.
- **Go 1.22+:** Required to build the operator.
- **Helm:** Deploys Tekton, SonarQube, and Grafeas.
- **Kind or an existing cluster:** To run the operator locally.
- **Git:** Clones the demonstration repository.

---

## Deploy a Kubernetes Cluster

Create a local cluster using Kind:

```bash
kind create cluster --name supply-chain-demo
```

Verify:

```bash
kubectl get nodes
```

---

## Install Tekton Pipelines

```bash
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
```

Verify:

```bash
kubectl get pods -n tekton-pipelines
```

---

## Install Tekton Chains

```bash
kubectl apply --filename https://storage.googleapis.com/tekton-releases/chains/latest/release.yaml
```

Verify:

```bash
kubectl get pods -n tekton-chains
```

---

## Bootstrap the Operator

Clone the repository:

```bash
git clone https://github.com/blanketops/secure-software-supply-chain.git
cd secure-software-supply-chain
```

Install CRDs:

```bash
make manifests
make install
```

Verify CRDs:

```bash
kubectl get crds | grep blanketops
```

---

## Configure a SupplyChain

Apply a SupplyChain CR for your repository:

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChain
metadata:
  name: secure-software-
  namespace: secure-software-supplychainsupply-chain
spec:
  repository: blanketops/secure-software-
  image:
    registry: ttl.sh
    name: secure-software-
    tagStrategy: git-sha
  steps:
    buildpacks: true
    trivy: true
    sign: true
    attest: true
    sonarQube:
      enabled: true
      serverURL: http://sonarqube.secure-software-supplychainsupply-chain.svc.cluster.local:9000
      tokenSecretRef:
        name: sonarqube-token
        key: token
    grafeas:
      enabled: true
      serverURL: http://grafeas.secure-software-supplychainsupply-chain.svc.cluster.local:8080
  signing:
    fulcioURL: https://fulcio.sigstore.dev
    rekorURL: https://rekor.sigstore.dev
  serviceAccountName: supply-chain-runner
```

Verify:

```bash
kubectl get supplychain -n secure-software-supplychainsupply-chain
```

---

## Trigger a Build

Create an ImageBuild CR to start the pipeline:

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: ImageBuild
metadata:
  name: secure-software--abc1234
  namespace: secure-software-supplychainsupply-chain
spec:
  supplyChainRef:
    name: secure-software-
  gitRef:
    url: https://github.com/blanketops/secure-software-
    revision: main
```

Watch the build:

```bash
kubectl get imagebuild -n secure-software-supplychainsupply-chain -w
```

You will see the phase move from `Pending` → `Running` → `Succeeded`. Per-step status is visible in:

```bash
kubectl describe imagebuild secure-software--abc1234 -n secure-software-supplychainsupply-chain
```

---

## Verify the Signed Image

Once the build succeeds, verify the image signature using Cosign:

```bash
cosign verify \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://oauth2.sigstore.dev/auth" \
  ttl.sh/secure-software-:<your-tag>
```

---

## Glossary

| Term                   | Description                                                                                         |
| ---------------------- | --------------------------------------------------------------------------------------------------- |
| **SupplyChain CR**     | Kubernetes custom resource defining the pipeline configuration for a repository. One per repo.      |
| **ImageBuild CR**      | Kubernetes custom resource representing a single pipeline execution. Create one to trigger a build. |
| **Tekton PipelineRun** | The Tekton resource that executes all pipeline steps. Owned by the ImageBuild controller.           |
| **Shipwright**         | A Kubernetes-native framework for building container images with a pluggable build strategy API.    |
| **Buildpacks**         | Cloud Native Buildpacks — builds OCI images from source without a Dockerfile.                       |
| **Trivy**              | Open-source vulnerability scanner for container images.                                             |
| **Cosign**             | A tool for signing and verifying container images. Part of the Sigstore project.                    |
| **Fulcio**             | A certificate authority for keyless code signing, backed by OIDC identity.                          |
| **Rekor**              | A public transparency log for signed artifacts. Records every signature immutably.                  |
| **Tekton Chains**      | A Tekton component that automatically generates SLSA provenance attestations for builds.            |
| **Grafeas**            | An open artifact metadata API for storing and querying build and security information.              |
| **SLSA**               | Supply chain Levels for Software Artifacts — a framework for supply chain security.                 |
| **SSOT**               | Single Source of Truth — the SupplyChain CR is the authoritative definition of the pipeline.        |
| **OCI**                | Open Container Initiative — the standard for container image formats and runtimes.                  |
| **Keyless signing**    | Signing without managing long-lived private keys — identity is verified via OIDC at signing time.   |

---

"Thank you for taking the time to engage with this demonstration. We hope it was worth your engineering efforts. This demonstration highlights how a combination of Tekton, Cosign, Buildpacks, and a Kubebuilder operator can deliver a complete software supply chain security pipeline on Kubernetes. It also demonstrates how the separation of concerns between a SupplyChain definition and an ImageBuild execution keeps the system clean and extensible."

## Acknowledgements

- [Tekton](https://tekton.dev)
- [Shipwright](https://shipwright.io)
- [Cosign / Sigstore](https://sigstore.dev)
- [Cloud Native Buildpacks](https://buildpacks.io)
- [Trivy](https://aquasecurity.github.io/trivy)
- [Tekton Chains](https://tekton.dev/docs/chains)
- [Grafeas](https://grafeas.io)
- [Kubebuilder](https://book.kubebuilder.io)
- [BlanketOps](https://github.com/blanketops)
