# secure-software-supply-chain

A Kubernetes operator that turns a git push into a container image that is built, scanned, signed, attested,
verified, and only then allowed to run. Built with Kubebuilder, driven by Tekton, secured by Sigstore.

> "Treat your pipeline as infrastructure, not a script."

---

## Demos

Short recordings of the real thing. The scripts that made them, and how to run them on your own cluster, are in
[`demo/`](demo/README.md).

**[A build, live in the Tekton Dashboard.](demo/README.md#demo-5-a-build-live-in-the-tekton-dashboard)** Nine
steps from clone to verified image, each turning green as it finishes, ending on what the last step verified.

![a build, live in the Tekton Dashboard](demo/5-tekton-dashboard/demo.gif)

**[From a push to a running, verified image.](demo/README.md#demo-4-from-a-push-to-a-running-verified-image)**
One `git push`. GitHub delivers it to the cluster, a build starts on its own, and the image it produces is signed,
logged and admitted.

![from a push to a running, verified image](demo/4-push-to-build/demo.gif)

**[Only what the supply chain built may run.](demo/README.md#demo-1-only-what-the-supply-chain-built-may-run)** The image the pipeline built is admitted; one signed by Tekton
Chains alone and one signed by nobody are refused, each refusal naming the policy behind it.

![only what the supply chain built may run](demo/1-admission/demo.gif)

**[No authorization, no identity, no certificate.](demo/README.md#demo-2-no-authorization-no-identity-no-certificate)** A build's ServiceAccount gets a signing identity only while it
passes three access reviews. Revoke one permission and the identity, and Fulcio's certificate with it, are gone
within a second.

![no authorization, no identity, no certificate](demo/2-revoke-identity/demo.gif)

**[What a build leaves behind.](demo/README.md#demo-3-what-a-build-leaves-behind)** One build from source to signed image, then the evidence for it, read back from
the registry and the transparency log.

![what a build leaves behind](demo/3-evidence/demo.gif)

---

## What it does

You declare a [`SupplyChain`](docs/usage.md#supplychain) for a repository and a
[`SupplyChainPolicy`](docs/concepts.md#enforcing-at-admission-supplychainpolicy) for what may run. From then on:

```
git push
  └── GitHub webhook ──► EventListener (Tekton Triggers)
        └── creates ──► ImageBuild
              └── owns ──► PipelineRun
                    1. git-clone                 fetch the source
                    2. authentication-fulcio     check the signing identity can reach Fulcio
                    3. code-scan-sonarqube       static analysis
                    4. build-image-buildah       build the image to a local archive
                    5. vulnerability-scan-trivy  scan the archive; any CRITICAL finding stops the build
                    6. push-image-docker         publish, and record the digest the registry serves
                    7. sign-image-cosign         keyless signature + authorization attestation
                    8. attest-image-rekor-fulcio hand the image to Tekton Chains for provenance
                    9. verify-image-policy       verify the published image the way admission will

kubectl apply (a workload)
  └── policy-controller ──► admits the image only if the SupplyChainPolicy is satisfied
```

What a successful build guarantees:

| Guarantee | How |
|---|---|
| No critical vulnerabilities | Trivy scans before the push; an image that fails is never published or signed |
| Signed by a known identity, with no long-lived keys | Cosign keyless: a Fulcio certificate issued to the build's identity, which [exists only while its ServiceAccount is authorized](docs/concepts.md#an-identity-is-granted-not-default) |
| Signed twice, by two identities | The build signs and attests its authorization; Tekton Chains signs and attests SLSA provenance. Admission requires all four. See [Two tiers of proof](docs/concepts.md#two-tiers-of-proof). |
| The signature is publicly witnessed | CT log proof in the certificate, Rekor entry for the signature |
| The build was authorized | [Three SubjectAccessReviews](docs/concepts.md#how-a-build-is-authorized), attested to the image |
| The signature is on the image you can pull | The digest signed is the one the registry serves |
| The image would be admitted | The last step verifies it against the same rules as [admission](docs/concepts.md#enforcing-at-admission-supplychainpolicy) |
| There is a record of all of it | [Evidence](docs/concepts.md#what-a-build-leaves-behind) read back from the registry and the transparency log |

---

## How it works, in brief

Three places hold the configuration, and each has one job:

| | Role | What it decides |
|---|---|---|
| Tekton Chains config | **Centre** | How the cluster signs: Fulcio, Rekor, the [identity provider](docs/concepts.md#signing-identity-kubernetes-or-spiffe), the provenance format |
| `SupplyChain` | **Authority** | Who may build and sign for a repository |
| `SupplyChainPolicy` | **Trust** | What is trusted at admission |

Every image carries proof from two independent identities, and admission requires all of it:

| Identity | What it adds to the image |
|---|---|
| The `SupplyChain`'s build ServiceAccount | A signature, and an attestation that the build was authorized |
| Tekton Chains | A signature, and SLSA v1.0 provenance of the run |

Signing is keyless: no long-lived keys exist anywhere in a build. With SPIFFE identities, a build ServiceAccount
has an identity, and so can get a certificate, only while it passes three SubjectAccessReviews.

[How it works](docs/concepts.md) explains each of these: [who decides what](docs/concepts.md#who-decides-what),
[how a build is authorized](docs/concepts.md#how-a-build-is-authorized),
[what admission requires](docs/concepts.md#enforcing-at-admission-supplychainpolicy) and
[what a build leaves behind](docs/concepts.md#what-a-build-leaves-behind).

---

## Resources

API group: `supplychain.blanketops.dev/v1alpha1`

| Kind | What it is |
|---|---|
| [`SupplyChain`](docs/usage.md#supplychain) | The pipeline definition for one repository. One per repository; the controller enforces it. Owns the Tekton tasks, the trigger stack, the EventListener ingress and the `supply-chain-runner` ServiceAccount. |
| [`SupplyChainPolicy`](docs/concepts.md#enforcing-at-admission-supplychainpolicy) | The admission side of a SupplyChain. Renders the policy-controller `TrustRoot` and `ClusterImagePolicies` that decide which of its images may run. |
| [`GitHubWebhook`](docs/usage.md#githubwebhook) | Registers the push webhook on the GitHub repository and keeps it registered. |
| [`ImageBuild`](docs/usage.md#trigger-a-build-by-hand) | One execution of the pipeline. Created by a push, or by hand. Owns the `PipelineRun` and tracks each step. |
| [`ImageSignature`](docs/concepts.md#how-a-build-is-authorized) | The record of the build's own signature, read back from the registry and Rekor: the signer, the certificate, the log index and when it was logged. |
| [`ImageBuildResult`](docs/concepts.md#what-a-build-leaves-behind) | The durable record of a build. Survives PipelineRun pruning. Git provenance, digest, scan counts, policy verification. |

---

## Getting started

Installation takes seven phases, from an empty cluster to a first verified build:

```
0  Prerequisites      a cluster, tools, External Secrets Operator
1  Dependencies       supplychain install     Tekton, Sigstore, SPIRE, ingress, SonarQube
2  Operator           make install deploy     the CRDs and the controller
3  Credentials        a ClusterSecretStore    git, registry, GitHub and SonarQube secrets
4  SonarQube          supplychain init-sonarqube
5  Resources          kubectl apply -k config/samples
6  Public webhook     Tailscale Funnel        so GitHub can reach the cluster
7  First build        an ImageBuild, then admission
```

[Installation](docs/installation.md) walks through each one. Two that people ask about first:
[creating the secret store](docs/installation.md#3-create-the-secret-store) and
[making the webhook reachable with Tailscale Funnel](docs/installation.md#6-make-the-webhook-reachable-tailscale-funnel).
Once it is running, [Usage](docs/usage.md) covers [following a build](docs/usage.md#follow-a-build) and
[reading its results](docs/usage.md#read-the-results), and [Troubleshooting](docs/troubleshooting.md) covers what
goes wrong.

## Documentation

| | |
|---|---|
| [Installation](docs/installation.md) | The seven phases above, including the secret store and Tailscale Funnel |
| [How it works](docs/concepts.md) | Identity, authorization, the two tiers of proof, admission, and evidence |
| [Usage](docs/usage.md) | The resources you write, following a build, reading its results, the CLI |
| [Troubleshooting](docs/troubleshooting.md) | What goes wrong and why |
| [Demos](demo/README.md) | The recordings above and how to make them again |

## Status

This is a working proof of concept, exercised end to end on a single-node kind cluster. Things to know before
relying on it:

- Credentials come from External Secrets' fake provider, which holds them in the cluster in plain form. A real
  deployment needs a real secret store.
- Fulcio, Rekor and SPIRE's OIDC discovery are reached over plain HTTP inside the cluster.
- The SPIFFE signing identity is the one exercised end to end. Under the Kubernetes identity, Tekton Chains'
  half of the proof has not been run.
- Branch names containing `/` cannot trigger a build yet.
- Admission reads an image's signatures from the registry for each of the four policies, and the webhook fails
  closed after ten seconds. On a slow link to the registry it can time out; running the workload again succeeds.
- The Trivy step uses a pre-built scanner image with the vulnerability database baked in, about 1 GB; its first
  pull on a new node can outlast the step's time limit. See [Troubleshooting](docs/troubleshooting.md).

---

## Development

```bash
make manifests generate   # after changing *_types.go or kubebuilder markers
make test                 # unit and controller tests (envtest)
make test-e2e             # creates its own kind cluster; allow 15-30 minutes
```

The e2e suite deploys the operator and the real policy-controller, and checks that a `SupplyChainPolicy` is
rendered, that an unsigned image is rejected, that warn mode admits it, and that deleting the policy cleans up.
It has no Fulcio or Rekor, so it does not cover a signed image being admitted; that path is exercised by a real
build.

---

## Acknowledgements

[Tekton](https://tekton.dev) ·
[Tekton Triggers](https://tekton.dev/docs/triggers) ·
[Tekton Chains](https://tekton.dev/docs/chains) ·
[Sigstore](https://sigstore.dev) ·
[Fulcio](https://github.com/sigstore/fulcio) ·
[Rekor](https://github.com/sigstore/rekor) ·
[Policy Controller](https://github.com/sigstore/policy-controller) ·
[Buildah](https://buildah.io) ·
[Skopeo](https://github.com/containers/skopeo) ·
[Trivy](https://aquasecurity.github.io/trivy) ·
[SonarQube](https://www.sonarqube.org) ·
[Kubebuilder](https://book.kubebuilder.io) ·
[External Secrets Operator](https://external-secrets.io) ·
[Tailscale Funnel](https://tailscale.com/kb/1223/funnel)
