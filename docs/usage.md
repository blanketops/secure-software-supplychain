# Usage

[← Back to the README](../README.md)

The resources you write, how to follow a build and read its results, and the CLI.

## SupplyChain

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
    fulcioURL: https://fulcio-server.fulcio-system.svc.cluster.local
    rekorURL: https://rekor-server.rekor-system.svc.cluster.local
    ctLogURL: https://ctlog.ctlog-system.svc/fulcio
```

## GitHubWebhook

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

## Trigger a build by hand

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

## Follow a build

```bash
kubectl get imagebuilds -n default -w            # Pending -> Running -> Succeeded | Failed
kubectl describe imagebuild <name>               # each step and how far it got
kubectl get imagesignatures -n default           # who signed, Rekor index
kubectl get imagebuildresults -n default         # digest, policy verification
tkn pipelinerun logs <name> -f
```

The Tekton Dashboard is at `http://supplychain.localhost:8888/dashboard/` once the ingress bridge is running
(see [Triggering builds from a push](installation.md#6-make-the-webhook-reachable-tailscale-funnel)), or without it:

```bash
kubectl port-forward -n tekton-pipelines svc/tekton-dashboard 9097:9097   # http://localhost:9097
```

## Read the results

The last step of a successful build prints what it verified:

```
Secure software supply chain policy verification
  Image:          docker.io/your-dockerhub-user/your-app:<sha>@sha256:...
  Signer:         spiffe://<your-domain>/ns/default/sa/supply-chain-runner
  Issuer:         https://spire-spiffe-oidc-discovery-provider.spire-server.svc.cluster.local
  Signature:      verified (Fulcio certificate, CT log proof, Rekor entry)
  Authorization:  verified (scope, intent, output allowed)
  Chains signer:  spiffe://<your-domain>/ns/tekton-chains/sa/tekton-chains-controller
  Chains:         verified (image signature, SLSA provenance)
  Rekor:          https://rekor-server.rekor-system.svc.cluster.local
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

## Deploy the image

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
supplychain install --only-step "Secret Store"   # set up, or repair, the store's login to Vault
supplychain secrets set <key>=<value|@file>      # store or rotate a credential in Vault
supplychain secrets list                         # which keys are set; never prints a value
supplychain secrets get <key>                    # the value Vault holds for one key
supplychain init-sonarqube --new-password <pw>   # bootstrap SonarQube; safe to run again
supplychain status                               # every dependency, certificate and the store; fails if one is not ready
supplychain uninstall                            # remove them
supplychain observe                              # one page: builds, signatures, the live log, permissions, credentials
```

## The observer

```bash
supplychain observe
```

opens one page in your browser, served from your machine, that shows one namespace at a time:

- **Supply chains**: what each builds, the identity it signs as, and the three permission checks it has to pass.
- **GitHub webhooks**: the webhook registered on each repository, where it delivers, GitHub's ID for it, and
  whether deliveries are signed with a shared secret.
- **Builds**: each build's steps, what the scans found, and every signature and attestation recorded for the
  image, with a link from each to its entry in the log.
- **Who is trusted**: read live from Fulcio, Rekor and the CT log. The log's signing key and Fulcio's root are
  compared with the trust anchors builds and admission verify against, so a log or a CA that is not the one the
  cluster trusts shows as such. It also shows which identity provider Fulcio issues certificates for, and how
  many signing certificates have been issued.
- **Transparency log**: the latest entries, decoded: what was signed, by which identity, vouched for by which
  provider, and whether the log returned a proof of inclusion. Search by log index, entry ID, or the SHA-256 of
  what was signed.
- **Permissions**: who may build and sign, and who may write admission policy. For each ServiceAccount it shows
  the three checks the operator made, which role and binding grant each one, and, when a check is refused, the
  exact Role and binding to apply to allow it.
- **Admission**: the policies and whose signatures they accept.
- **Credentials**: the secret store, where it is, how it logs in (a SPIFFE identity, a ServiceAccount, or a
  stored token) and whether it is reached over verified HTTPS; then what builds are reading from it right now,
  never the values.
- **Activity**: recent events.

It reads everything through `kubectl proxy`, including Rekor, Fulcio and the CT log, which the Kubernetes API
proxies to. It therefore works wherever `kubectl` does, needs your kubeconfig to allow `get` on
`services/proxy` in the three sigstore namespaces, and changes nothing in the cluster. The Kubernetes API does
not verify a Service's certificate when it proxies to it, which is why what is read is checked against the
trust anchors rather than taken on the connection's word.

## Remove a SupplyChain

```bash
kubectl delete githubwebhook <name>-webhook      # takes the webhook off the GitHub repository
kubectl delete supplychainpolicy <name>          # removes its ClusterImagePolicies and TrustRoot
kubectl delete supplychain <name>
```

Deleting a `SupplyChain` removes what it created: its builds and their runs, the trigger objects, the
EventListener and its ingress, and its SPIFFE registration. The build ServiceAccount and the three Tasks the
operator adds to the namespace are shared by every `SupplyChain` there, so they go with the last one; the same
holds for a policy's ServiceAccount. A ServiceAccount you created yourself is never removed, and neither are the
roles you applied from `config/samples`.

## Uninstall

```bash
mage undeploy
mage uninstall
supplychain uninstall
```

`supplychain uninstall` removes the policy-controller CRDs, which deletes every `ClusterImagePolicy` and
`TrustRoot` with them. It also removes Vault and its volume, and with them every credential stored there.
