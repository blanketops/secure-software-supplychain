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
    fulcioURL: http://fulcio-server.fulcio-system.svc.cluster.local
    rekorURL: http://rekor-server.rekor-system.svc.cluster.local
    ctLogURL: http://ctlog.ctlog-system.svc/fulcio
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
supplychain secrets set <secret> <field>=<value|@file>   # store or rotate a credential in Vault
supplychain secrets list                         # which fields are set; never prints a value
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
`TrustRoot` with them. It also removes Vault and its volume, and with them every credential stored there.
