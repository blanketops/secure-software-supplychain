# Installation

[← Back to the README](../README.md)

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

## 0. Prerequisites

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

## 1. Install the dependencies

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
| `--signing-identity` | How builds prove who they are to Fulcio: `spiffe` (recommended) or `kubernetes` (default). See [Signing identity](concepts.md#signing-identity-kubernetes-or-spiffe). |
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

## 2. Deploy the operator

```bash
docker build -t <registry>/supply-chain-controller:<tag> .
kind load docker-image <registry>/supply-chain-controller:<tag> --name <cluster>   # or docker push

make install                                              # the CRDs
make deploy IMG=<registry>/supply-chain-controller:<tag>  # the controller
```

## 3. Create the secret store

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

## 4. Bootstrap SonarQube

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

## 5. Apply the roles and the resources

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

## 6. Make the webhook reachable: Tailscale Funnel

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

## 7. Check it with one build

Push a commit, or start a build by hand (see [Trigger a build by hand](usage.md#trigger-a-build-by-hand)), then:

```bash
kubectl get imagebuilds -n default -w           # Pending -> Running -> Succeeded
kubectl get imagesignatures,imagebuildresults -n default
```

A finished build has an `ImageSignature` that is `Signed`, with the Rekor index of its signature, and an
`ImageBuildResult` whose evidence lists the build's and Chains' signatures and attestations. Run the image in a
namespace labelled `policy.sigstore.dev/include=true`: it is admitted, and an image this pipeline did not build
is refused.
