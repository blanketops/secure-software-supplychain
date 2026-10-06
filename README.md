# secure-software-supply-chain

A Kubernetes operator that turns a git push into a container image that is built, scanned, signed, attested,
verified, and only then allowed to run. Built with Kubebuilder, driven by Tekton, secured by Sigstore.

> "Treat your pipeline as infrastructure, not a script."

It is part of the [BlanketOps](https://github.com/blanketops) platform engineering project.

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
| Signed by a known identity, with no long-lived keys | Cosign keyless: a Fulcio certificate issued to the build's identity, which exists only while its ServiceAccount is authorized |
| Signed twice, by two identities | The build signs and attests its authorization; Tekton Chains signs and attests SLSA provenance. Admission requires all four. |
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
| `ImageSignature` | The record of the build's own signature, read back from the registry and Rekor: the signer, the certificate, the log index and when it was logged. |
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
identities from the trust domain and nothing else, and gives Tekton Chains the Workload API socket. Fulcio then
refuses Kubernetes ServiceAccount tokens: a pod cannot get a certificate with the token it already has, only
with an identity that was registered for it. The pipeline's sign, attest and
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
Fulcio issues it nothing. The checks run again whenever a Role, RoleBinding, ClusterRole or ClusterRoleBinding
changes, so a revoked permission takes the identity away within a second, and every five minutes regardless.
When one fails the registration is removed and the `SupplyChain` reports `Unauthorized`, with the three answers
in `status.authorization`. [Demo 2](#demo-2-no-authorization-no-identity-no-certificate) shows it.

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
$ kubectl get imagebuildresult your-app-1 -o jsonpath='{.status.evidence}' | jq
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

The controller holds no signing material. The steps that sign obtain their own certificate from Fulcio inside the
build, with the build's identity; the operator has no permission to mint ServiceAccount tokens.

**Gate 3: the PipelineRun.** Created with the proofs injected. An `ImageSignature` is created as `Pending` first,
so the signing identity is on record before anything runs.

After signing, the three proofs are attached to the image with `cosign attest` (predicate type
`https://blanketops.dev/attestations/authorization/v1`), signed by the same keyless identity. The signature says
who built the image. The attestation says that identity was authorized, according to the API server, when it did.

When the PipelineRun finishes, the controller records an `ImageBuildResult` and prunes old PipelineRuns (the
last 3 succeeded and 1 failed are kept).

The `ImageSignature` is then completed from the evidence, not from the outcome of the run. It becomes `Signed`
only when the build's signature is found on the image together with its Rekor entry, and its fields are that
signature's own: the certificate subject and issuer, the certificate itself, the log index and ID, and the time
the log accepted it. A build that succeeded but whose signature could not be read stays `Pending`, and the
`Signed` condition says why. A failed build is marked `Failed`.

---

## Enforcing at admission: SupplyChainPolicy

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChainPolicy
metadata:
  name: your-app
spec:
  supplyChainRef:
    name: your-app
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
kubectl get supplychainpolicy your-app -n default -o yaml
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

## Installation

Installation has seven phases. Phases 1 to 5 set up the platform once per cluster; phase 6 makes builds start on
a push; phase 7 checks the whole thing with one build.

```
0  Prerequisites           a cluster, tools, External Secrets Operator
1  Dependencies            supplychain install       Tekton, Sigstore, SPIRE, ingress, SonarQube   (≈ 20 min to hours)
2  Operator                make install deploy       the CRDs and the controller
3  Credentials             ClusterSecretStore        git, registry, GitHub and SonarQube secrets   (yours, kept out of git)
4  SonarQube               supplychain init-sonarqube
5  Resources               kubectl apply -k config/samples   roles, SupplyChain, SupplyChainPolicy
6  Public webhook          Tailscale Funnel           GitHub reaches the cluster
7  First build             an ImageBuild, then admission
```

Every name in angle brackets is yours to fill in. The examples use `your-org/your-app` for the GitHub repository,
`your-dockerhub-user/your-app` for the image and `your-machine.your-tailnet.ts.net` for the public hostname.

### 0. Prerequisites

- A Kubernetes cluster. Everything here is tested on a single-node [kind](https://kind.sigs.k8s.io/) cluster.
  Give it room: as a rough guide, 8 GB of memory and 40 GB of free disk for images and volumes. SonarQube's search index
  stops working when the node's disk is more than 90% full.
- `kubectl`, `docker`, Go 1.25, `helm`, and `git`.
- A container registry you can push to, a GitHub repository with a `Dockerfile` at its root, and a GitHub token
  that can manage that repository's webhooks.
- [External Secrets Operator](https://external-secrets.io). The installer does not install it:

  ```bash
  helm install external-secrets external-secrets \
    --repo https://charts.external-secrets.io \
    -n external-secrets --create-namespace
  ```

### 1. Install the dependencies

```bash
go build -o bin/supplychain ./cmd/cli
./bin/supplychain install \
  --webhook-host your-machine.your-tailnet.ts.net \
  --signing-identity spiffe --trust-domain <your-domain>
```

| Flag | Meaning |
|---|---|
| `--webhook-host` | The public hostname GitHub will deliver pushes to (phase 6). Only the webhook is routed on it. |
| `--ui-host` | The hostname of the Tekton Dashboard and SonarQube. Default `supplychain.localhost`, reachable from your machine only. Never the webhook host: the dashboard has no login. |
| `--signing-identity` | How builds prove who they are to Fulcio: `spiffe` (recommended) or `kubernetes` (default). See [Signing identity](#signing-identity-kubernetes-or-spiffe). |
| `--trust-domain` | The SPIFFE trust domain, for example your organisation's domain. Identities look like `spiffe://<your-domain>/ns/<namespace>/sa/<serviceaccount>`. |
| `--from-step` | Resume at a named step, for example `--from-step "Rekor"`. |

The installer applies the steps below in order and waits for each to be ready. Each wait allows up to an hour,
because on a slow connection almost all of the time is image pulls.

| Step | What it sets up |
|---|---|
| MetalLB | A load-balancer address for the ingress controller on a local cluster |
| Tekton Pipelines, Triggers, Interceptors | The build engine and the webhook receiver |
| SPIRE CRDs, SPIRE, SPIRE Identities | *`spiffe` only.* The identity provider, its CSI driver and OIDC discovery, and the identities it may hand out: Tekton Chains, and nothing else until a `SupplyChain` registers its build ServiceAccount |
| Fulcio | The certificate authority, with its CT log, trusting exactly one issuer: SPIRE, or the Kubernetes API server |
| Rekor | The transparency log, with its Trillian database and a signing key that survives restarts |
| Tekton Chains | Signs every run and records SLSA v1.0 provenance next to the image |
| Policy Controller | Admission: refuses images that do not satisfy a `SupplyChainPolicy` |
| Tekton Dashboard, Tasks, Results | The UI, the pipeline's task definitions, and long-term run history |
| NGINX Ingress Controller, Ingress Routes | The webhook route on `--webhook-host`, the UIs on `--ui-host` |
| SonarQube | Static analysis, on a PostgreSQL database and volumes of its own |

It also collects the sigstore trust anchors (Fulcio root, Rekor key, CT log key) into the
`blanketops-sigstore-roots` ConfigMap, which the pipeline and the policies verify against.

**Re-running it is safe.** What must only be made once is never made again: the keys Fulcio, the CT log and
Rekor sign with, the Merkle trees behind Rekor and the CT log, and the SonarQube database password. If an
install stops on a timeout, run it again with `--from-step` set to the step it stopped at.

```bash
./bin/supplychain status        # every dependency and whether it is ready
```

### 2. Deploy the operator

```bash
docker build -t <registry>/supply-chain-controller:<tag> .
kind load docker-image <registry>/supply-chain-controller:<tag> --name <cluster>   # or docker push

make install                                              # the CRDs
make deploy IMG=<registry>/supply-chain-controller:<tag>  # the controller
```

### 3. Create the secret store

The operator reads every credential from a `ClusterSecretStore` named `secure-software-supply-chain-store`
(External Secrets, fake provider) and syncs what each build needs into ordinary Secrets. The store holds real
credentials: **create it from a file outside the repository and never commit it.**

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: secure-software-supply-chain-store
spec:
  provider:
    fake:
      data:
      - key: /supplychain/git/ssh-privatekey      # an SSH key that can read the repository
        value: |
          -----BEGIN OPENSSH PRIVATE KEY-----
          <your private key>
          -----END OPENSSH PRIVATE KEY-----
      - key: /supplychain/git/ssh-publickey
        value: <your public key>
      - key: /supplychain/git/known-hosts         # ssh-keyscan github.com
        value: <github.com host keys>
      - key: /supplychain/git/ssh-config
        value: <ssh client config for the git host, if you need one>
      - key: /supplychain/registry/config         # a Docker config.json with push access
        value: '{"auths":{"https://index.docker.io/v1/":{"auth":"<base64 of user:token>"}}}'
      - key: /supplychain/github/pat              # a token that can manage the repository's webhooks
        value: <github token>
      - key: /supplychain/github/token
        value: <github token>
      - key: /supplychain/sonarqube/token         # written for you in phase 4
        value: ""
```

```bash
kubectl apply -f <path-outside-the-repo>/secretstore.yaml
```

Use a registry access token rather than a password, and a GitHub fine-grained token limited to the repository.
A GitHub deploy key belongs to exactly one repository; the store has one SSH key for every `SupplyChain`, so
for more than one repository use a machine user's key.

Synced Secrets are not refreshed when the store changes, except the SonarQube token. After changing any other
value, delete the synced Secret and External Secrets recreates it.

### 4. Bootstrap SonarQube

SonarQube starts with `admin` / `admin`. The bootstrap sets your admin password, generates a `supply-chain`
token and writes it into the store:

```bash
./bin/supplychain init-sonarqube --new-password '<password>'
```

SonarQube requires at least 12 characters with upper case, lower case, a digit and a special character.

The command reaches SonarQube through a port-forward to its pod, so it runs from wherever your kubeconfig
works. It is safe to run again: the password is only set while it is still the default, and a new token is only
generated when the one in the store is missing or SonarQube no longer accepts it. When it does replace the token,
it also refreshes the Secrets the builds read it from.

SonarQube keeps its users, tokens, settings and analysis in a PostgreSQL database (`sonarqube-postgresql`), and
its search index and plugins on a volume of its own; both survive restarts and re-running the installer. The
database password is generated by the installer on first install and kept in the `sonarqube-postgresql` Secret.
It is never replaced, because PostgreSQL only reads it when it initialises an empty volume. Delete that Secret
only together with the two volumes.

### 5. Apply the roles and the resources

Edit the samples first: `config/samples/supplychain_v1alpha1_supplychain.yaml` names your repository, image and
public hostname, and `supplychain_v1alpha1_githubwebhook.yaml` names your repository and hostname again.

```bash
kubectl apply -k config/samples
```

This applies the signing, event-listener and policy-runner roles, the `SupplyChain`, the `GitHubWebhook` and the
`SupplyChainPolicy`. The roles grant the build ServiceAccount the three permissions it is reviewed for before it
is given an identity, and the policy ServiceAccount the three it needs before a policy is rendered.

```bash
kubectl get supplychain,supplychainpolicy,githubwebhook -n default
kubectl get clusterimagepolicies,trustroots
```

The `SupplyChain` should be `Ready` with `status.signingIdentity` set, and the policy `Ready=True`. A
`SupplyChain` that reports `Unauthorized` lists in `status.authorization` which of the three checks failed.

### 6. Make the webhook reachable: Tailscale Funnel

GitHub has to reach the cluster's EventListener over HTTPS. A local cluster has no public address, and
[Tailscale Funnel](https://tailscale.com/kb/1223/funnel) gives it one, with a valid certificate, without a cloud
load balancer or opening a port on your router.

```
GitHub ──https──► your-machine.your-tailnet.ts.net   (Tailscale Funnel, public, TLS)
                     └──► localhost:8888              (socat on your machine)
                            └──► MetalLB IP:80        (ingress-nginx in the cluster)
                                   └──► EventListener (routed only for --webhook-host)
```

**Enable Funnel for your tailnet** (once, in the Tailscale admin console): turn on HTTPS certificates under
*DNS*, and allow Funnel for your machine in the access-control policy:

```json
"nodeAttrs": [{ "target": ["autogroup:member"], "attr": ["funnel"] }]
```

**Find your machine's public name.** It is the webhook host for phase 1 and the samples:

```bash
sudo tailscale up
tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//'    # your-machine.your-tailnet.ts.net
```

**Bridge a local port to the ingress controller.** On kind, the address MetalLB gives ingress-nginx is only
reachable from the machine itself, so a small forwarder carries traffic from a local port to it:

```bash
INGRESS_IP=$(kubectl get svc -n ingress-nginx ingress-nginx-controller \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

sudo tee /etc/systemd/system/kind-ingress-bridge.service <<EOF
[Unit]
Description=Bridge localhost:8888 to kind ingress-nginx
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:8888,fork,reuseaddr TCP:${INGRESS_IP}:80
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now kind-ingress-bridge
```

**Publish the port:**

```bash
tailscale funnel --bg 8888
tailscale funnel status          # https://your-machine.your-tailnet.ts.net (Funnel on) -> 127.0.0.1:8888
```

The `GitHubWebhook` then registers the push webhook on your repository, pointing at that hostname, and keeps it
registered. Every push creates an `ImageBuild` named `<supplychain>-<branch>-<commit-sha>`.

What is public and what is not:

- Funnel publishes everything served on that hostname, so ingress routes **only the webhook** there.
- The Tekton Dashboard and SonarQube are routed on `--ui-host` (`supplychain.localhost` by default), which
  resolves only on your machine: `http://supplychain.localhost:8888/dashboard/` and
  `http://supplychain.localhost:8888/sonarqube/`.
- Set a webhook secret (`spec.webhookSecretRef` on the `GitHubWebhook`) so that only GitHub's deliveries start
  builds.
- `tailscale funnel reset` takes the hostname off the internet again.

> **Branch names containing `/`** cannot trigger a build yet: the branch is part of the build's name.

### 7. Check it with one build

Push a commit, or start a build by hand (see [Trigger a build by hand](#trigger-a-build-by-hand)), then:

```bash
kubectl get imagebuilds -n default -w           # Pending -> Running -> Succeeded
kubectl get imagesignatures,imagebuildresults -n default
```

A finished build has an `ImageSignature` that is `Signed`, with the Rekor index of its signature, and an
`ImageBuildResult` whose evidence lists the build's and Chains' signatures and attestations. Run the image in a
namespace labelled `policy.sigstore.dev/include=true`: it is admitted, and an image this pipeline did not build
is refused.

---

## Usage

### SupplyChain

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChain
metadata:
  name: your-app
  namespace: default
spec:
  repository: your-org/your-app
  serviceAccountName: supply-chain-runner
  webhookHost: your-machine.your-tailnet.ts.net
  image:
    registry: docker.io
    name: your-dockerhub-user/your-app
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
      projectKey: your-org_your-app
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
  name: your-app-webhook
  namespace: default
spec:
  repository: your-org/your-app
  supplyChainRef:
    name: your-app
  hookURL: https://your-machine.your-tailnet.ts.net
  events: [push]
  secretRef:
    name: github-app-credentials
```

### Trigger a build by hand

```yaml
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: ImageBuild
metadata:
  name: your-app-manual-001
  namespace: default
spec:
  supplyChainRef:
    name: your-app
  gitRef:
    url: git@github.com:your-org/your-app.git
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
  Image:          docker.io/your-dockerhub-user/your-app:<sha>@sha256:...
  Signer:         spiffe://<your-domain>/ns/default/sa/supply-chain-runner
  Issuer:         http://spire-spiffe-oidc-discovery-provider.spire-server.svc.cluster.local
  Signature:      verified (Fulcio certificate, CT log proof, Rekor entry)
  Authorization:  verified (scope, intent, output allowed)
  Chains signer:  spiffe://<your-domain>/ns/tekton-chains/sa/tekton-chains-controller
  Chains:         verified (image signature, SLSA provenance)
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
kubectl run app --image=docker.io/your-dockerhub-user/your-app:<sha>
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

They differ when Fulcio's CA was regenerated after the trust anchors were collected. The installer no longer
re-runs the Jobs that make the keys, so this only happens if those keys were deleted by hand. Restart
`fulcio-server` and `ctlog`, and make sure the CT log's trusted root (`ctlog-secret`, key `fulcio-0`) is the
current Fulcio root.

**Fulcio returns 500 "Error entering certificate in CTL".** Same cause, seen from the other side: the CT log
does not trust Fulcio's current root.

**Re-running the installer.** It is safe: steps that already ran are applied again without replacing what must
only be made once. The keys Fulcio, the CT log and Rekor sign with, and the Merkle trees behind Rekor and the CT
log, are created on first install and never again. (A new tree would be a new, empty log: every earlier signature
would be "not found in the transparency log" and its image refused.) Use `--from-step "<name>"` to resume at a
step.

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

## Demos

Terminal recordings in the same style as [knative-ctl](https://github.com/ntlaletsi70/knative-ctl): `k9s`
watching the demo namespace on top, a scripted run of the real commands below, recorded with
[asciinema](https://asciinema.org) and rendered with [agg](https://github.com/asciinema/agg) inside a `screen`
split. Every script is in [`demo/`](demo/), so each recording can be made again on your own cluster.

Demos 1 and 3 use real images and a real build. The scripts display the image repository, the git repository
and the `SupplyChain`'s name as `your-dockerhub-user/your-app`, `your-org/your-app` and `your-app`; the `mask`
function in each script is the only thing that changes what is shown.

### Demo 1: only what the supply chain built may run

![only what the supply chain built may run](demo/1-admission/demo.gif)

Three images of one repository are run in a namespace the policy controller guards. The image the pipeline
built, signed by the build and by Tekton Chains, is admitted and becomes a pod (top pane). An image signed by
Chains alone is refused by the policy that wants the build's own signature. An image pushed by hand is refused
by all four policies, each named with its reason.

Re-run it with three such images of your own:

```bash
kubectl create namespace admission-demo
kubectl label namespace admission-demo policy.sigstore.dev/include=true

export REPO=docker.io/<user>/<app> APP=<supplychain> \
       SIGNED_TAG=<tag> CHAINS_ONLY_TAG=<tag> UNSIGNED_TAG=<tag>
asciinema rec demo/1-admission/demo.cast -c "screen -c demo/1-admission/screenrc"
agg --idle-time-limit 2 demo/1-admission/demo.cast demo/1-admission/demo.gif
```

### Demo 2: no authorization, no identity, no certificate

![no authorization, no identity, no certificate](demo/2-revoke-identity/demo.gif)

The `your-app` SupplyChain's build ServiceAccount passes its three reviews, so SPIRE gives a pod running as it
an identity and Fulcio issues that identity a signing certificate. Another ServiceAccount in the same namespace
gets no identity, and Fulcio will not take its Kubernetes token instead. Deleting the RoleBinding that grants
the three permissions turns the SupplyChain `Unauthorized` at once (top pane), and the same pod is refused an
identity. Putting the RoleBinding back restores both.

Re-run it on a cluster installed with `--signing-identity spiffe`, with the operator deployed:

```bash
kubectl apply -f demo/2-revoke-identity/setup.yaml
asciinema rec demo/2-revoke-identity/demo.cast -c "screen -c demo/2-revoke-identity/screenrc"
agg demo/2-revoke-identity/demo.cast demo/2-revoke-identity/demo.gif
```

It needs `k9s`, `screen`, `python3` and `openssl` on your machine. `ask-fulcio.sh` makes the same certificate
request a signing step does and prints one line per outcome; it never prints a token or a key.

### Demo 3: what a build leaves behind

![what a build leaves behind](demo/3-evidence/demo.gif)

One real build, start to finish: an `ImageBuild` is applied, the nine steps run as pods (top pane), and the last
step prints what it verified. Then the evidence, read back from the registry and Rekor rather than assumed:

- the `ImageSignature`, whose Rekor index is the one cosign printed inside the build and the one Rekor holds an
  entry at;
- the `ImageBuildResult`, listing all seven signatures and attestations with their signer, key and log index,
  complete once Tekton Chains has signed the finished run;
- the same record in Tekton, as a `CustomRun`.

The build takes about four minutes; the recording caps every pause at two seconds and plays in about a minute
and a half.

```bash
export APP=<supplychain> REPO=docker.io/<user>/<app> GIT_REPO=<org>/<repo> REVISION=<branch>
asciinema rec demo/3-evidence/demo.cast -c "screen -c demo/3-evidence/screenrc"
agg --idle-time-limit 2 demo/3-evidence/demo.cast demo/3-evidence/demo.gif
```

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


