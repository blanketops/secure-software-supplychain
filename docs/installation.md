# Installation

[← Back to the README](../README.md)

Installation has seven phases. Phases 1 to 5 set up the platform once per cluster; phase 6 makes builds start on
a push; phase 7 checks the whole thing with one build.

```
0  Prerequisites           a cluster, tools, External Secrets Operator
1  Dependencies            supplychain install       Tekton, Sigstore, SPIRE, Vault, ingress, SonarQube   (≈ 20 min to hours)
2  Operator                make install deploy       the CRDs and the controller
3  Credentials             supplychain secrets set   git, registry and GitHub credentials, kept in Vault
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
| `--only-step` | Run one step and nothing else, for example `--only-step "Vault"`. |
| `--external-secret-store` | Do not install Vault; you provide the secret store. See [Using a secret store of your own](#using-a-secret-store-of-your-own). |

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
| Vault | Where the credentials are kept, and the `ClusterSecretStore` External Secrets reads them through. Skipped with `--external-secret-store`. |
| SonarQube | Static analysis, on a PostgreSQL database and volumes of its own |

It also collects the sigstore trust anchors (Fulcio root, Rekor key, CT log key) into the
`blanketops-sigstore-roots` ConfigMap, which the pipeline and the policies verify against.

**Re-running it is safe.** What must only be made once is never made again: the keys Fulcio, the CT log and
Rekor sign with, the Merkle trees behind Rekor and the CT log, Vault's unseal key and root token, and the
SonarQube database password. If an
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

## 3. Store the credentials

Builds need four credentials. They are kept in [HashiCorp Vault](https://www.vaultproject.io), which the
installer runs, and reach each build as ordinary Kubernetes Secrets through External Secrets Operator.

```
Vault (secret/supplychain/…) ──► ClusterSecretStore ──► ExternalSecret ──► Secret ──► build pod
       you write here            created by the          created by the operator
                                 installer               for each build
```

Put them in with the CLI. A value starting with `@` is read from that file, which is how keys and other
multi-line values are given, and keeps them out of your shell history:

```bash
supplychain secrets set git      ssh-privatekey=@<path-to-private-key> \
                                 known-hosts=@<file from: ssh-keyscan github.com> \
                                 ssh-config=@<ssh-client-config>
supplychain secrets set registry config=@<docker config.json with push access>
supplychain secrets set github   token=@<file holding a GitHub token>

supplychain secrets list         # which fields are set; never prints a value
```

These are the store's keys. Every build asks the store for exactly these secrets and fields:

| Secret | Field | What it is |
|---|---|---|
| `supplychain/git` | `ssh-privatekey` | An SSH key that can read the repository |
| | `known-hosts` | The git host's keys, for example from `ssh-keyscan github.com` |
| | `ssh-config` | SSH client configuration for the git host |
| `supplychain/registry` | `config` | A Docker `config.json` with push access: `{"auths":{"https://index.docker.io/v1/":{"auth":"<base64 of user:token>"}}}` |
| `supplychain/github` | `token` | A token that can manage the repository's webhooks |
| `supplychain/sonarqube` | `token` | Written for you in phase 4 |

Use a registry access token rather than a password, and a GitHub fine-grained token limited to the repository.
A GitHub deploy key belongs to exactly one repository; there is one SSH key for every `SupplyChain`, so for more
than one repository use a machine user's key.

**Rotating a credential** is the same command again. `set` changes the fields you name and keeps the rest, and
External Secrets re-reads every secret each minute, so the new value reaches the builds without anything being
deleted or restarted.

### How the store is set up

The installer's `Vault` step does this once, and can be run again safely:

- starts one Vault server with its data on a volume, initialises it, and enables a key-value engine at `secret/`;
- enables Kubernetes auth, with a role bound to a single ServiceAccount (`vault/supply-chain-secrets`) and a
  policy that can **read** `secret/supplychain/*` and nothing else;
- creates the `ClusterSecretStore` named `secure-software-supply-chain-store`, which logs in as that
  ServiceAccount. The store holds no token or password.

The operator never talks to Vault and has no Vault credential. It only creates `ExternalSecret` objects that
point at the store.

The store the installer creates is this one, also in
[`config/samples/externalsecrets_v1_clustersecretstore_vault.yaml`](../config/samples/externalsecrets_v1_clustersecretstore_vault.yaml):

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: secure-software-supply-chain-store
spec:
  provider:
    vault:
      server: http://vault.vault.svc.cluster.local:8200
      path: secret              # the key-value (version 2) engine
      version: v2
      auth:
        kubernetes:             # no token in the store: it logs in as a ServiceAccount
          mountPath: kubernetes
          role: supply-chain
          serviceAccountRef:
            name: supply-chain-secrets
            namespace: vault
```

An `ExternalSecret` the operator creates then asks it for a field of a secret, for example the SSH key:

```yaml
spec:
  refreshInterval: 1m
  secretStoreRef: { name: secure-software-supply-chain-store, kind: ClusterSecretStore }
  data:
  - secretKey: id_rsa
    remoteRef: { key: supplychain/git, property: ssh-privatekey }
```

> **Vault's own keys are in the cluster.** Vault seals itself whenever its pod restarts, and a sidecar unseals
> it with a key the installer keeps in the `vault-unseal` Secret, next to Vault's root token. That is what makes
> the install self-contained, and it means anyone who can read Secrets in the `vault` namespace can open Vault.
> It is right for a demonstration and wrong for production: there, use one of Vault's
> [auto-unseal](https://developer.hashicorp.com/vault/docs/concepts/seal#auto-unseal) mechanisms, remove the
> Secret, and revoke the root token.

### Using a secret store of your own

Vault is what the installer sets up, not something the operator depends on. The operator reads through
External Secrets, so any [provider](https://external-secrets.io/latest/introduction/stability-support/) it
supports will do: AWS Secrets Manager, Google Secret Manager, Azure Key Vault, an existing Vault, and so on.

The operator owns the `ExternalSecret` objects: it creates them for each build and puts them back if they are
changed, so what they ask for is fixed. Your store has to answer to the same names:

- a `ClusterSecretStore` called **`secure-software-supply-chain-store`**;
- the four secrets in the table above, under the same keys (`supplychain/git`, `supplychain/registry`,
  `supplychain/github`, `supplychain/sonarqube`);
- each holding the same fields. The operator asks for a field as a `property` of the secret, so in a store that
  keeps one value per secret, the value is a JSON object with those fields.

[`config/samples/externalsecrets_v1_clustersecretstore_aws.yaml`](../config/samples/externalsecrets_v1_clustersecretstore_aws.yaml)
is an example for AWS Secrets Manager, with the same names. It is a starting point and has not been run as part
of this project's tests.

Install without Vault, and have the SonarQube bootstrap hand you the token instead of writing it to Vault:

```bash
supplychain install --external-secret-store --webhook-host <host> ...
supplychain init-sonarqube --new-password '<password>' --token-file <file>
# then store the contents of <file> as supplychain/sonarqube, field "token"
```

## 4. Bootstrap SonarQube

SonarQube starts with `admin` / `admin`. The bootstrap sets your admin password, generates a `supply-chain`
token and writes it to Vault:

```bash
./bin/supplychain init-sonarqube --new-password '<password>'
```

SonarQube requires at least 12 characters with upper case, lower case, a digit and a special character.

The command reaches SonarQube through a port-forward to its pod, so it runs from wherever your kubeconfig
works. It is safe to run again: the password is only set while it is still the default, and a new token is only
generated when the one in Vault is missing or SonarQube no longer accepts it. When it does replace the token,
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
