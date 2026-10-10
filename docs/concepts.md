# How it works

[← Back to the README](../README.md)

What each resource decides, how a build is authorized, what admission requires, and what a build leaves behind
as proof. For setting it up see [Installation](installation.md); for day-to-day commands see [Usage](usage.md).

- [Who decides what](#who-decides-what)
- [How a build is authorized](#how-a-build-is-authorized)
- [Enforcing at admission: SupplyChainPolicy](#enforcing-at-admission-supplychainpolicy)
- [What a build leaves behind](#what-a-build-leaves-behind)

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
in `status.authorization`. [Demo 2](../demo/README.md#demo-2-no-authorization-no-identity-no-certificate) shows it.

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

---

## How a build is authorized

Before a build starts, the `ImageBuild` controller runs three gates in order.

**Gate 1: prerequisites.** The git SSH key, registry credentials and SonarQube token are synced from Vault by
External Secrets, through a `ClusterSecretStore`. The build waits until all of them exist.

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

## What a build leaves behind

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
