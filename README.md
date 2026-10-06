# secure-software-supply-chain

A Kubernetes operator that turns a git push into a container image that is built, scanned, signed, attested,
verified, and only then allowed to run. Built with Kubebuilder, driven by Tekton, secured by Sigstore.

> "Treat your pipeline as infrastructure, not a script."

It is part of the [BlanketOps](https://github.com/ntlaletsi70) platform engineering project.

---

## What it does

You declare a `SupplyChain` for a repository and a `SupplyChainPolicy` for what may run. From then on:

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
| Signed by a known identity, with no long-lived keys | Cosign keyless: a Fulcio certificate issued to the pipeline's ServiceAccount |
| The signature is publicly witnessed | CT log proof in the certificate, Rekor entry for the signature |
| The build was authorized | Three SubjectAccessReviews, attested to the image |
| The signature is on the image you can pull | The digest signed is the one the registry serves |
| The image would be admitted | The last step verifies it against the same rules as admission |

---

## Resources

API group: `supplychain.blanketops.dev/v1alpha1`

| Kind | What it is |
|---|---|
| `SupplyChain` | The pipeline definition for one repository. One per repository; the controller enforces it. Owns the Tekton tasks, the trigger stack, the EventListener ingress and the `supply-chain-runner` ServiceAccount. |
| `SupplyChainPolicy` | The admission side of a SupplyChain. Renders the policy-controller `TrustRoot` and `ClusterImagePolicies` that decide which of its images may run. |
| `GitHubWebhook` | Registers the push webhook on the GitHub repository and keeps it registered. |
| `ImageBuild` | One execution of the pipeline. Created by a push, or by hand. Owns the `PipelineRun` and tracks each step. |
| `ImageSignature` | The signing record of a build: who signed, with which certificate, and the Rekor index. |
| `ImageBuildResult` | The durable record of a build. Survives PipelineRun pruning. Git provenance, digest, scan counts, policy verification. |

![Supply Chain Architecture](docs/architecture.png)

---

## Who decides what

Three places hold the configuration, and each has one job:

| | Role | What it decides |
|---|---|---|
| Tekton Chains config | **Centre** | The signing configuration of the cluster: Fulcio, Rekor, the OIDC issuer, the identity provider, the provenance format. The installer writes it, Chains signs provenance from it, and the operator reads the same values for the pipeline's signatures and for the admission policy. |
| `SupplyChain` | **Authority** | Who may build and sign for a repository: the ServiceAccount, checked by three SubjectAccessReviews before every build. |
| `SupplyChainPolicy` | **Trust** | What is trusted at admission: which signers, under which sigstore. |

### Signing identity: Kubernetes or SPIFFE

How a workload proves who it is to Fulcio is a cluster-wide choice, made at install time:

| `--signing-identity` | Credential | Name in the certificate |
|---|---|---|
| `kubernetes` (default) | A projected ServiceAccount token | `https://kubernetes.io/namespaces/<ns>/serviceaccounts/<sa>` |
| `spiffe` | A JWT-SVID from [SPIRE](https://spiffe.io), fetched over the SPIFFE Workload API | `spiffe://<trust-domain>/ns/<ns>/sa/<sa>` |

With `spiffe`, the installer also installs SPIRE (server, agent, CSI driver, OIDC discovery), tells Fulcio to accept
identities from the trust domain, and gives Tekton Chains the Workload API socket. The pipeline's sign, attest and
verify steps and the default signers of every `SupplyChainPolicy` follow, because they all read the identity from
the Chains config (`signers.x509.fulcio.provider` and `.issuer`) and the trust domain from Tekton's `config-spire`.

The three authorization proofs are unaffected: they are about the Kubernetes ServiceAccount the API server
reviewed, whatever name the certificate carries.

### An identity is granted, not default

Under `spiffe` no pod has a SPIFFE identity unless one was registered for it. The installer leaves out SPIRE's
default rule, which gives every pod in the cluster an identity, and registers exactly two kinds:

| Who | Registered by | When |
|---|---|---|
| Tekton Chains' controller | The installer | At install |
| A `SupplyChain`'s build ServiceAccount | The `SupplyChain` controller | Only while the ServiceAccount passes its three authorization checks |

Fulcio certifies whatever SPIRE vouches for, so this is where the three SubjectAccessReviews gate signing itself:
a ServiceAccount that may not read the `SupplyChain`, start builds and record signatures has no identity, and
Fulcio issues it nothing. The checks are repeated every five minutes; when one fails the registration is removed
and the `SupplyChain` reports `Unauthorized`, with the three answers in `status.authorization`.

### Two tiers of proof

Every image a build produces carries proof from two independent identities, and both are required:

| Tier | Identity | What it adds to the image |
|---|---|---|
| Authority | The `SupplyChain`'s build ServiceAccount | A signature, and an attestation of the three authorization proofs |
| Centre | Tekton Chains' controller | A signature, and SLSA v1.0 provenance of the run |

Chains signs first, as soon as the push completes; the build's sign step waits for that signature before adding
its own, because both are stored under the same registry tag. The last pipeline step verifies all four, and a
`SupplyChainPolicy` renders four `ClusterImagePolicy` objects (`<ns>-<name>`, `-authorization`, `-chains`,
`-provenance`). An image must pass every one of them to be admitted, so neither identity can vouch for an image
on its own.

### What a build leaves behind

`ImageBuildResult` is the record of a build. Besides the outcome of each step it holds the evidence for the
image, read back from the registry and the transparency log once the build is over:

```console
$ kubectl get imagebuildresult for-kaniko-app-1 -o jsonpath='{.status.evidence}' | jq
```

| Field | What it says |
|---|---|
| `signatures[]` | Every signature and attestation on the image: `kind`, `predicateType`, `signedBy` (`Build`, `Chains` or `Other`), the certificate `subject` and `issuer`, the `keyFingerprint` and `certificateFingerprint`, and its transparency log entry (`rekorLogIndex`, `rekorLogID`, `integratedAt`) |
| `trustAnchors` | Fingerprints of the Fulcio root, the Rekor key and the CT log key in use |
| `provenanceLogEntry` | Where Chains logged the provenance of the whole run |
| `complete` | True once Chains has finished with the run and nothing more will be added |

The same record is published to Tekton as a `CustomRun` named `<pipelinerun>-result`, whose results are a summary
of it, so a build's outcome and evidence can be read in Tekton next to the run that produced them
(`kubectl get customrun -l blanketops.dev/supply-chain=<name>`). It is a run of its own and not a task of the
build's pipeline: Tekton Chains only signs a `PipelineRun` whose children are all `TaskRun`s, and a custom task
inside the pipeline would cost the run its provenance.

> **Status.** Both identities have been run end to end on a cluster. With `spiffe`: Fulcio issued SPIFFE
> certificates to the build and to Chains, the pipeline verified both tiers, and admission accepted the image
> while rejecting one that carried only Chains' signature and one that was unsigned. The Chains tier has not
> been run under the `kubernetes` identity.

## How a build is authorized

Before a build starts, the `ImageBuild` controller runs three gates in order.

**Gate 1: prerequisites.** The git SSH key, registry credentials and SonarQube token are synced from the
`ClusterSecretStore` by External Secrets. The build waits until all of them exist.

**Gate 2: three proofs.** Three SubjectAccessReviews are performed for the `supply-chain-runner` ServiceAccount.
All three must be allowed:

| Proof | Resource | Verb | Meaning |
|-------|----------|------|---------|
| Scope | `supplychains` | `get` | The ServiceAccount can see the chain it builds for |
| Intent | `imagebuilds` | `create` | It may start a build |
| Output | `imagesignatures` | `create` | It may produce signing records |

Then a short-lived token is minted for the ServiceAccount and exchanged with Fulcio for a signing certificate.

**Gate 3: the PipelineRun.** Created with the proofs injected. An `ImageSignature` is created as `Pending` first,
so the signing identity is on record before anything runs.

After signing, the three proofs are attached to the image with `cosign attest` (predicate type
`https://blanketops.dev/attestations/authorization/v1`), signed by the same keyless identity. The signature says
who built the image. The attestation says that identity was authorized, according to the API server, when it did.

When the PipelineRun finishes, the controller records an `ImageBuildResult`, marks the `ImageSignature` `Signed`
or `Failed`, and prunes old PipelineRuns (the last 3 succeeded and 1 failed are kept).

---

## Enforcing at admission: SupplyChainPolicy

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChainPolicy
metadata:
  name: for-kaniko-app
spec:
  supplyChainRef:
    name: for-kaniko-app
  mode: enforce                                    # or warn
  serviceAccountName: supply-chain-policy-runner   # default
  signers:
  - serviceAccountName: supply-chain-runner
  trustRoot:
    fulcio:
      url: http://fulcio-server.fulcio-system.svc.cluster.local
      pemRef: {name: blanketops-sigstore-roots, key: fulcio-root.pem}
    rekor:
      url: http://rekor-server.rekor-system.svc.cluster.local
      pemRef: {name: blanketops-sigstore-roots, key: rekor.pub}
    ctLog:
      url: http://ctlog.ctlog-system.svc/fulcio
      pemRef: {name: blanketops-sigstore-roots, key: ctfe.pub}
```

Only `supplyChainRef` is required. Everything else defaults to what the SupplyChain signs with:

| Field | Default |
|---|---|
| Image glob | `SupplyChain.spec.image`, as `registry/name**` (not configurable) |
| `signers` | The SupplyChain's ServiceAccount and the cluster OIDC issuer |
| `trustRoot.*.url` | `SupplyChain.spec.signing` |
| `trustRoot.*.pemRef` | The matching key of the `blanketops-sigstore-roots` ConfigMap in the same namespace |

State `signers` to accept more than one identity. State `trustRoot` to trust a different sigstore.

### What gets rendered

One `TrustRoot` and two `ClusterImagePolicies`, all cluster-scoped and named `<namespace>-<name>`. An image is
admitted only if it passes both policies:

| Check | Policy |
|---|---|
| Signed keylessly by one of the signers, with a Fulcio certificate chaining to the trust root | `<namespace>-<name>` |
| That certificate has a CT log proof and the signature is in Rekor | `<namespace>-<name>` |
| Carries an authorization attestation, signed the same way, with scope, intent and output all allowed | `<namespace>-<name>-authorization` |

A wrong Fulcio root, Rekor key or CT log key each cause rejection, as does a missing signature or attestation.

### The policy is authorized too

A policy is rendered on behalf of its own ServiceAccount, `supply-chain-policy-runner` by default, which the
controller creates. Nothing is rendered until it passes three SubjectAccessReviews:

| Proof | Resource | Verb | Meaning |
|-------|----------|------|---------|
| Scope | `supplychains` | `get` | It can read the SupplyChain it sets policy for |
| Intent | `supplychainpolicies` | `create` | It may declare admission policy for it |
| Output | `clusterimagepolicies` (`policy.sigstore.dev`) | `create` | It may produce the admission policies |

Grant them with `config/samples/supplychain_v1alpha1_policyrole.yaml`. Until then the policy is `Ready=False`
with reason `AuthorizationDenied`. Policies that were already rendered stay in place, so losing the grant does
not silently turn enforcement off.

### Reading the status

```bash
kubectl get supplychainpolicies -n default -o wide
kubectl get supplychainpolicy for-kaniko-app -n default -o yaml
```

| Status field | Meaning |
|---|---|
| `conditions[Ready]` | Whether the rendered resources are in sync. The reason says why not. |
| `authorization` | The verdict of each of the three reviews. |
| `signers`, `fulcioURL`, `rekorURL`, `ctLogURL` | What the spec and the SupplyChain resolved to. |
| `trustAnchors` | SHA-256 fingerprints of the Fulcio root and the two log keys in the `TrustRoot`. |
| `clusterImagePolicies`, `trustRoot` | Names of the rendered resources. |

### Turning enforcement on

policy-controller only acts in namespaces that opt in:

```bash
kubectl label namespace <workload-namespace> policy.sigstore.dev/include=true
```

---

## Install

Tested on a [kind](https://kind.sigs.k8s.io/) cluster.

### Prerequisites

- A cluster, `kubectl`, `docker`, Go.
- [External Secrets Operator](https://external-secrets.io). The installer does not install it:

  ```bash
  helm install external-secrets external-secrets \
    --repo https://charts.external-secrets.io \
    -n external-secrets --create-namespace
  ```

### 1. Install the dependencies

```bash
go build -o bin/supplychain ./cmd/cli
./bin/supplychain install --webhook-host <public-hostname> [--ui-host <private-hostname>] \
  [--signing-identity spiffe --trust-domain <domain>]
```

This applies, in order: MetalLB, Tekton Pipelines, Triggers, Interceptors, Fulcio (with its CT log), Rekor,
Tekton Chains, policy-controller, Tekton Dashboard, the Tekton tasks, Tekton Results, the NGINX ingress
controller, the ingress routes and SonarQube. It also collects the sigstore trust anchors into the
`blanketops-sigstore-roots` ConfigMap.

Each wait allows up to an hour, because on a slow connection the time is almost all image pulls.
See [Troubleshooting](#troubleshooting) if it stalls.

### 2. Deploy the operator

```bash
docker build -t blanketops/supply-chain-controller:latest .
kind load docker-image blanketops/supply-chain-controller:latest --name <cluster>

make install
make deploy IMG=blanketops/supply-chain-controller:latest
```

### 3. Create the secret store

The operator reads its credentials from a `ClusterSecretStore` named `secure-software-supply-chain-store`
(External Secrets, fake provider). It holds real credentials, so **keep it outside the repository**:

```bash
kubectl apply -f ~/supplychain_v1alpha1_secretsstore.yaml
```

| Key | Content |
|---|---|
| `/supplychain/git/ssh-privatekey`, `/supplychain/git/ssh-publickey` | SSH key that can read the source repository |
| `/supplychain/git/known-hosts`, `/supplychain/git/ssh-config` | SSH client configuration for the git host |
| `/supplychain/registry/config` | Docker `config.json` with push access to the registry |
| `/supplychain/sonarqube/token` | SonarQube user token (written by step 4) |
| `/supplychain/github/pat`, `/supplychain/github/token` | GitHub token that can manage the repository's webhooks |

A GitHub deploy key belongs to exactly one repository. The store has a single SSH key shared by every
SupplyChain, so for more than one repository use a machine user's key.

The synced Kubernetes Secrets do not refresh on their own. After changing a value in the store, delete the
Secret and External Secrets recreates it.

### 4. Bootstrap SonarQube

SonarQube starts with `admin` / `admin`. The bootstrap sets a new admin password, generates a `supply-chain`
token and writes it into the store:

```bash
./bin/supplychain init-sonarqube --new-password '<password>'
```

SonarQube requires at least 12 characters with upper case, lower case, a digit and a special character.

The command reaches SonarQube through a port-forward to its pod, so it runs from wherever your kubeconfig
works. It is safe to run again: the password is only set while it is still the default, and a new token is only
generated when the one in the store is missing or SonarQube no longer accepts it. When it does replace the token,
it also refreshes the Secrets the builds read it from.

SonarQube keeps its users, tokens, settings and analysis in a PostgreSQL database
(`sonarqube-postgresql`), and its search index and plugins on a volume of its own; both survive restarts and
re-running the installer. The database password is generated by the installer on first install and kept in the
`sonarqube-postgresql` Secret. It is never replaced, because PostgreSQL only reads it when it initialises an empty
volume.

### 5. Apply the roles and the resources

```bash
kubectl apply -k config/samples
```

This applies the signing, event-listener and policy-runner roles, the `SupplyChain`, the `GitHubWebhook` and
the `SupplyChainPolicy`.

Check:

```bash
kubectl get supplychain,supplychainpolicy,githubwebhook -n default
kubectl get clusterimagepolicies,trustroots
```

---

## Triggering builds from a push

GitHub has to reach the EventListener. On a local cluster, [Tailscale Funnel](https://tailscale.com/kb/1223/funnel)
gives it a public hostname without a cloud load balancer.

```bash
# Bridge a local port to the ingress address assigned by MetalLB
sudo tee /etc/systemd/system/kind-ingress-bridge.service <<EOF
[Unit]
Description=Bridge localhost to kind ingress-nginx
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:8888,fork,reuseaddr TCP:<metallb-ingress-ip>:80
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now kind-ingress-bridge

# Publish it
sudo tailscale up
tailscale funnel --bg 8888
```

Set that hostname as `spec.webhookHost` on the `SupplyChain` and as `spec.hookURL` on the `GitHubWebhook`. The
`GitHubWebhook` then registers the webhook, and every push creates an `ImageBuild` named
`<supplychain>-<branch>-<commit-sha>`.

Funnel publishes everything served on that hostname, so only the webhook is routed there. The Tekton Dashboard
and SonarQube have ingresses of their own on a separate hostname (`--ui-host`, default `supplychain.localhost`)
that is only reachable from the machine itself:

```
http://supplychain.localhost:8888/dashboard/
http://supplychain.localhost:8888/sonarqube/
```

Do not set `--ui-host` to the webhook host: the dashboard has no login.

> **Branch names containing `/`** cannot trigger a build yet: the branch is part of the build's name.

---

## Usage

### SupplyChain

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChain
metadata:
  name: for-kaniko-app
  namespace: default
spec:
  repository: ntlaletsi70/for-kaniko-app
  serviceAccountName: supply-chain-runner
  webhookHost: your-machine.tailf8145.ts.net
  image:
    registry: docker.io
    name: nkanyezisolutions/for-kaniko-app
    tagStrategy: git-sha
    cloneSecret: github-ssh-credentials
    registrySecret: registry-credentials
  steps:
    trivy: true
    sign: true
    attest: true
    sonarQube:
      serverURL: http://sonarqube-sonarqube.default.svc.cluster.local:9000/sonarqube
      tokenSecretRef: sonarqube-token
      projectKey: ntlaletsi70_for-kaniko-app
  signing:
    fulcioURL: http://fulcio-server.fulcio-system.svc.cluster.local
    rekorURL: http://rekor-server.rekor-system.svc.cluster.local
    ctLogURL: http://ctlog.ctlog-system.svc/fulcio
```

### GitHubWebhook

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: GitHubWebhook
metadata:
  name: for-kaniko-app-webhook
  namespace: default
spec:
  repository: ntlaletsi70/for-kaniko-app
  supplyChainRef:
    name: for-kaniko-app
  hookURL: https://your-machine.tailf8145.ts.net
  events: [push]
  secretRef:
    name: github-app-credentials
```

### Trigger a build by hand

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

### Follow a build

```bash
kubectl get imagebuilds -n default -w            # Pending -> Running -> Succeeded | Failed
kubectl describe imagebuild <name>               # each step and how far it got
kubectl get imagesignatures -n default           # who signed, Rekor index
kubectl get imagebuildresults -n default         # digest, policy verification
tkn pipelinerun logs <name> -f
```

The Tekton Dashboard is at `http://supplychain.localhost:8888/dashboard/` once the ingress bridge is running
(see [Triggering builds from a push](#triggering-builds-from-a-push)), or without it:

```bash
kubectl port-forward -n tekton-pipelines svc/tekton-dashboard 9097:9097   # http://localhost:9097
```

### Read the results

The last step of a successful build prints what it verified:

```
Supply chain policy verification
  Image:          docker.io/nkanyezisolutions/for-kaniko-app:<sha>@sha256:...
  Signer:         https://kubernetes.io/namespaces/default/serviceaccounts/supply-chain-runner
  Issuer:         https://kubernetes.default.svc.cluster.local
  Signature:      verified (Fulcio certificate, CT log proof, Rekor entry)
  Authorization:  verified (scope, intent, output allowed)
  Rekor:          http://rekor-server.rekor-system.svc.cluster.local
  Result:         PASS
```

The same outcome is recorded on the `ImageBuildResult`, under `status.buildResults`:

| Field | Meaning |
|---|---|
| `commit`, `committerDate`, `repoURL` | What was built |
| `imageURL`, `imageDigest` | What was published. Empty if the build stopped before the push. |
| `trivyScanSummary`, `trivyCriticalCount`, `trivyHighCount`, `trivyTotalCount` | Scan outcome. Recorded even when the scan stops the build. |
| `policyVerification` | `PASS` when the last step verified the signature and the attestation |
| `verifiedSigner` | The identity they were verified against |

```bash
kubectl get imagebuildresult <name> -n default \
  -o custom-columns='PHASE:.status.phase,POLICY:.status.buildResults.policyVerification,CRITICAL:.status.buildResults.trivyCriticalCount,HIGH:.status.buildResults.trivyHighCount'
```

### Deploy the image

In a namespace labelled `policy.sigstore.dev/include=true`:

```bash
kubectl run app --image=docker.io/nkanyezisolutions/for-kaniko-app:<sha>
```

An image the SupplyChain built is admitted. Anything else under that repository is rejected, and the message
names the policy that refused it.

---

## CLI

```bash
supplychain install --webhook-host <host>        # install the dependencies (--ui-host for the UIs)
supplychain init-sonarqube --new-password <pw>   # bootstrap SonarQube; safe to run again
supplychain status                               # check the dependencies
supplychain uninstall                            # remove them
supplychain observe                              # supply chain dashboard
supplychain observe rbac                         # RBAC audit dashboard
```

## Uninstall

```bash
make undeploy
make uninstall
supplychain uninstall
```

`supplychain uninstall` removes the policy-controller CRDs, which deletes every `ClusterImagePolicy` and
`TrustRoot` with them.

---

## Troubleshooting

**The installer stalls or a setup Job fails.** Image pulls dominate install time. The kubelet pulls one image
at a time by default; on kind, allow parallel pulls by adding `serializeImagePulls: false` and
`maxParallelImagePulls: 8` to `/var/lib/kubelet/config.yaml` on the node and restarting the kubelet. The
sigstore setup Jobs give up after six attempts; if one ran before the service it needs was up (for example
`rekor-trillian-createdb` before MySQL), delete it and re-apply it from `dependencies/`.

**A signed image is rejected with "certificate signed by unknown authority".** The policy trusts a Fulcio root
that is not the one that signed. Compare the two:

```bash
kubectl get supplychainpolicy <name> -o jsonpath='{.status.trustAnchors.fulcioRoot}'
curl -s http://<fulcio>/api/v1/rootCert | openssl x509 -outform DER | sha256sum
```

They differ when Fulcio's CA was regenerated after the trust anchors were collected. That happens if the
installer is run again after the setup Jobs have been cleaned up: the Jobs are re-created and generate new keys
while Fulcio and the CT log keep the old ones in memory. Restart `fulcio-server` and `ctlog`, and make sure the
CT log's trusted root (`ctlog-secret`, key `fulcio-0`) is the current Fulcio root.

**Fulcio returns 500 "Error entering certificate in CTL".** Same cause, seen from the other side: the CT log
does not trust Fulcio's current root.

**SonarQube restarts with "No shard available".** Its Elasticsearch refuses to allocate indexes when the disk
is more than 90% full. Free space on the node's disk.

**A build fails at `vulnerability-scan-trivy`.** If the message is a timeout, the scanner image (about 1 GB)
was still downloading; the next build uses the cached image. If it reports critical vulnerabilities, that is
the gate: update the base image.

**A build fails at `git-clone` with "Permission denied (publickey)".** The key in the store cannot read the
repository. Remember the synced Secret has to be deleted after the store changes.

**A policy is `Ready=False`.** The reason says which input is missing: `AuthorizationDenied`,
`SupplyChainNotFound`, `SigningDisabled`, `TrustAnchorsNotFound`, `TrustAnchorsInvalid`,
`PolicyControllerNotInstalled` or `ApplyFailed`.

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

## Part of BlanketOps

- [blanketops-environments-controller](https://github.com/ntlaletsi70) — environment orchestration
- [blanketops-environments-supply-chain](https://github.com/ntlaletsi70/secure-software-supply-chain) — supply chain pipeline (this repo)
- [blanketops-zenith-runners-pool](https://github.com/ntlaletsi70) — GitHub Actions self-hosted runners

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

See [`demo/`](demo/) for a recorded walkthrough.
