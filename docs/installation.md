# Installation

[← Back to the README](../README.md)

Installation has seven phases. Phases 1 to 5 set up the platform once per cluster; phase 6 makes builds start on
a push; phase 7 checks the whole thing with one build.

```
0  Prerequisites           a cluster, tools, External Secrets Operator
1  Dependencies            supplychain install       cert-manager, Tekton, Sigstore, SPIRE, Vault, ingress, SonarQube   (≈ 20 min to hours)
2  Operator                mage install deploy       the CRDs and the controller, built with ko
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

  The install pulls about seventy images, and a kubelet downloads one at a time unless it is told otherwise.
  Letting it download several at once is the single largest saving in install time. On kind, create the
  cluster with the configuration in this repository, or change one that already exists:

  ```bash
  kind create cluster --name <cluster> --config hack/kind-cluster.yaml
  ```
- `kubectl`, Go 1.25, `helm`, and `git`. [mage](https://magefile.org) is optional: every `mage <target>` below
  can be run as `go run mage.go <target>`. No Docker is needed to build the operator.
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
| `--key-residency` | Where Fulcio's and Rekor's signing keys are kept: `cluster` (default) or `vault`. See [Where the signing keys are kept](#where-the-signing-keys-are-kept). |
| `--allow-trust-change` | Let `--signing-identity`, `--trust-domain` or `--key-residency` differ from what the cluster was installed with. See [The installer remembers](#the-installer-remembers). |
| `--vault-addr` | Use a Vault that already exists, at this address, instead of running one. See [Using a Vault you already have](#using-a-vault-you-already-have). |
| `--external-secret-store` | No Vault at all; you provide the secret store. See [Using a secret store of your own](#using-a-secret-store-of-your-own). |

The installer applies the steps below in order and waits for each to be ready. You name the packages to
install — there is no "install everything" in one command. Each package pulls its own images when it is
applied; almost all of the install's time is those pulls.

```
[1/2] Fulcio
  ✓ Fulcio applied
[2/2] Rekor
  ✓ Rekor applied
```

An image's wait allows up to an hour, so a slow pull does not force a re-run. On kind, where the node pulls
one image at a time by default, create the cluster with `hack/kind-cluster.yaml`, which turns on parallel
pulls and speeds up installing several packages at once.

### The install order

This is the exact order `supplychain install` applies the packages, as the
installer defines it. Each is a package name you can give to `install` (its
slug — lowercase, spaces to hyphens, e.g. `metallb-install`, `tekton-chains`).
A step whose condition is not met is skipped; the number is its position in a
full `spiffe`, `--key-residency vault` install.

| # | Package | Condition to run |
|---|---|---|
| 1 | MetalLB Install | always |
| 2 | cert-manager | unless the cluster already runs its own |
| 3 | Certificate Authority | always |
| 4 | Tekton Pipelines | always |
| 5 | Tekton Triggers | always |
| 6 | Tekton Interceptors | always |
| 7 | SPIRE CRDs | `--signing-identity spiffe` |
| 8 | SPIRE | `--signing-identity spiffe` — includes the Tornjak UI sidecars |
| 9 | SPIRE Identities | `--signing-identity spiffe` |
| 10 | Vault | unless `--vault-addr` or `--external-secret-store` |
| 11 | Signing Keys | `--key-residency vault` |
| 12 | Fulcio | always |
| 13 | Rekor | always |
| 14 | Tekton Chains | always |
| 15 | Policy Controller | always |
| 16 | Tekton Dashboard | always |
| 17 | Tekton Tasks | always |
| 18 | Tekton Results | always |
| 19 | Tekton Pruner | always |
| 20 | MetalLB Dependencies | always |
| 21 | NGINX Ingress Controller | always |
| 22 | Ingress Routes | always |
| 23 | Secret Store Identity | `--signing-identity spiffe`, unless `--vault-addr`/`--external-secret-store` |
| 24 | Secret Store | unless `--external-secret-store` |
| 25 | SonarQube | always |

The order is not arbitrary — later steps depend on earlier ones. SPIRE comes
before Fulcio (Fulcio is told to trust SPIRE's issuer); Vault before Fulcio and
Rekor (which may sign with keys it holds); the NGINX controller before the
Ingress routes (the admission webhook must be up first). Installing a single
package with `install <name>` does NOT pull its prerequisites in — install them
first, or run the full install. `supplychain install --list` prints the names.

The table below is the same steps grouped by what they set up.

| Step | What it sets up |
|---|---|
| MetalLB | A load-balancer address for the ingress controller on a local cluster |
| cert-manager | Issues and renews TLS certificates. Skipped when the cluster already runs a cert-manager of its own, which is then used as it is. |
| Certificate Authority | A private CA, and the `ClusterIssuer` `supply-chain-ca` that signs with it. Its certificate is what every client of the secure software supply chain's services trusts. |
| Tekton Pipelines, Triggers, Interceptors | The build engine and the webhook receiver |
| SPIRE CRDs, SPIRE, SPIRE Identities | *`spiffe` only.* The identity provider, its CSI driver and OIDC discovery, the Tornjak UI (sidecars in the SPIRE server pod, cluster-internal), and the identities it may hand out: Tekton Chains, and nothing else until a `SupplyChain` registers its build ServiceAccount |
| Vault | Where the credentials are kept, and with `--key-residency vault` the signing keys. Skipped with `--vault-addr` and with `--external-secret-store`. |
| Signing Keys | *`--key-residency vault` only.* Fulcio's and Rekor's keys, made inside Vault, and Fulcio's root certificate issued from the one Vault holds. |
| Fulcio | The certificate authority, with its CT log, trusting exactly one issuer: SPIRE, or the Kubernetes API server |
| Rekor | The transparency log, with its Trillian database and a signing key that survives restarts |
| Tekton Chains | Signs every run and records SLSA v1.0 provenance next to the image |
| Policy Controller | Admission: refuses images that do not satisfy a `SupplyChainPolicy` |
| Tekton Dashboard, Tasks, Results | The UI, the pipeline's task definitions, and long-term run history |
| Tekton Pruner | Deletes every PipelineRun and TaskRun 15 minutes after it finishes, succeeded or failed (`dependencies/tekton/pruner/retention/retention.yaml`). Runs stay long enough for Chains to sign them and for the operator to record that evidence; Results keeps their history and logs. |
| NGINX Ingress Controller, Ingress Routes | The webhook route on `--webhook-host`, the UIs on `--ui-host` |
| Secret Store Identity | *`spiffe` only.* The store's own SPIFFE identity: SPIRE issues it to one ServiceAccount, and a small pod keeps the current JWT-SVID where External Secrets can present it. Skipped with `--vault-addr` and with `--external-secret-store`. |
| Secret Store | A login to Vault for External Secrets, limited to reading the secure software supply chain's secrets, and the `ClusterSecretStore` that uses it. With `spiffe` the login is that SPIFFE identity and nothing else. Skipped with `--external-secret-store`. |
| SonarQube | Static analysis, on a PostgreSQL database and volumes of its own |

It also collects the sigstore trust anchors (Fulcio root, Rekor key, CT log key) into the
`blanketops-sigstore-roots` ConfigMap, which the pipeline and the policies verify against.

### The installer remembers

Three settings decide what a cluster trusts: `--signing-identity`, `--trust-domain` and `--key-residency`.
Changing one replaces a trust anchor, and nothing signed before the change verifies after it. So they are
recorded when a cluster is installed (in the ConfigMap `kube-system/secure-software-supply-chain-install`), and
every later run starts from there:

- **A flag you leave out keeps the cluster's value**, not the default. Running the installer again with a flag
  forgotten changes nothing.

  ```
     Kept from this cluster's install: --key-residency vault, --signing-identity spiffe, --trust-domain <your-domain>
  ```
- **A flag that contradicts the cluster is refused**, before anything is applied, and the refusal says what
  would be replaced.
- **`--allow-trust-change` makes the change on purpose.** Expect to rebuild every image afterwards.

`--webhook-host` is remembered too, and may be changed freely. A cluster installed before settings were
recorded is read from what runs on it.

### Where the signing keys are kept

Two keys are roots of trust. Whoever holds the key Fulcio signs certificates with can issue a signing
certificate for any identity; whoever holds the key Rekor signs the log with can make the log vouch for entries
that were never made. `--key-residency` decides where they live:

| | `cluster` (default) | `vault` |
|---|---|---|
| Where the keys are | Files in Kubernetes Secrets | Vault's Transit engine |
| Who can copy them | Anyone who can read Secrets in `fulcio-system` or `rekor-system` | Nobody: they are not exportable, through Vault's API included |
| How the services sign | They load the key | They ask Vault to, each for its own key and nothing else |
| Record of what was signed | None | Vault's audit log, when enabled |
| Fulcio and Rekor depend on | Nothing else | Vault being up and unsealed |

```bash
supplychain install --key-residency vault --signing-identity spiffe ...
```

With `vault`, the `Signing Keys` step creates the two keys in Vault before either service starts, and issues
Fulcio's root certificate by having Vault sign it, so the installer never sees a private key either. Each
service's pod gets a `vault-agent` container that logs in as the pod's own ServiceAccount, keeps the token fresh
and adds it to the service's requests; the service itself holds no Vault credential. The policies are narrow:
sign and verify with one key, and read its public half. A pod may restart once while it starts, if the service
is up before its agent has logged in.

```bash
kubectl exec -n vault vault-0 -c vault -- vault list transit/keys          # fulcio-ca, rekor
kubectl exec -n vault vault-0 -c vault -- vault read transit/keys/rekor    # public half, exportable: false
```

#### Looking at the keys while they are in use

```bash
supplychain keys
```

```
Vault 2.0.3, shamir seal, unsealed

fulcio-ca
  kind         ecdsa-p256, version 1, made 2026-10-11 22:18
  public key   sha256:f04fd5…
  leaves Vault no: it cannot be exported, backed up in the clear, or deleted
  signs for    fulcio-system/fulcio-server, and nobody else
  signing      allowed
  used         24 times in the audit log, last 2026-10-12 02:41:07
```

The count comes from Vault's audit log, which the `Signing Keys` step turns on. Vault writes one line to its
own output for every request it serves, with secrets hashed: which key signed, when, and for which service.
`kubectl logs -n vault vault-0 -c vault | grep transit/sign` is the full record.

#### Switching a key off, and on again

Where the keys are kept is decided once, at install time, and is not something to switch back and forth; see
[The installer remembers](#the-installer-remembers). What can be switched at any moment is whether a service may
*use* its key:

```bash
supplychain keys suspend fulcio     # no new signing certificates
supplychain keys suspend rekor      # no new log entries or signed tree heads
supplychain keys resume fulcio
```

It takes effect on the service's next request, with no restart, because Vault checks a token's policy every
time. It leaves the key, the service's login and everything already signed as they are: images that verified
before still verify and are still admitted, since admission checks signatures against the trust anchors and
asks nobody to sign. What stops is new signing, so builds fail at their sign step until it is resumed. Running
the installer again does not resume a suspended service.

A sealed Vault has the same effect on both services at once. The pod's own sidecar unseals it again within a
few seconds; restarting Vault's pod interrupts signing for about half a minute, and the services recover
without being restarted.

#### What protects the keys

This keeps a key the way a hardware security module does, in software. Be clear about what protects it:

- **It is as strong as Vault's seal.** The installer leaves Vault's unseal key in a Secret next to it, so that
  it can restart unattended. While that is so, the root of trust has moved, not gone. Unsealing Vault from a
  cloud KMS or a hardware device outside the cluster
  ([auto-unseal](https://developer.hashicorp.com/vault/docs/concepts/seal#auto-unseal)) is what completes it, and
  the same configuration is then backed by hardware.
- **Choose it before the first build, and do not change it afterwards.** The keys are trust anchors: switching
  residency makes new ones, and nothing signed before verifies against them. The installer refuses to switch
  unless you pass `--allow-trust-change`.
- **Fulcio's root certificate is kept twice.** It is issued once, when the key is made, and a certificate
  issued later for the same key would not be valid at the time earlier signatures were made. Besides the Secret
  Fulcio reads it from, a copy is kept in Vault, and the `Signing Keys` step puts the Secret back from it if the
  Secret is ever overwritten.
- **It needs the Vault the installer runs.** It cannot yet be combined with `--vault-addr` or
  `--external-secret-store`, and other key services (a cloud KMS, a PKCS#11 device), which Fulcio and Rekor
  both support, are not wired into the installer.

### TLS between the services

Every service of the secure software supply chain is reached over HTTPS only, with a certificate from the private CA above:

| Service | Address |
|---|---|
| Rekor | `https://rekor-server.rekor-system.svc.cluster.local` |
| Fulcio | `https://fulcio-server.fulcio-system.svc.cluster.local` |
| CT log | `https://ctlog.ctlog-system.svc/fulcio` |
| Vault | `https://vault.vault.svc.cluster.local:8200` |
| SPIRE OIDC discovery | `https://spire-spiffe-oidc-discovery-provider.spire-server.svc.cluster.local` |

Rekor, Fulcio, the CT log and Vault do not serve their HTTP API over TLS in a way that follows a renewed
certificate. Each listens on its pod's loopback address, where nothing outside the pod reaches it, and a `tls`
container in the same pod serves it on the Service's port. Fulcio's gRPC port is closed the same way and is no
longer exposed. SPIRE's discovery provider already sits behind nginx, which serves the certificate. cert-manager
renews the certificates (90 days, renewed after 60) and each container picks a new one up within the hour, so
nothing is restarted, which matters for Vault: a restart seals it.

Who verifies whom, always against the CA and in addition to the public CAs an image already trusts:

- the pipeline's cosign steps and the operator, for Fulcio and Rekor, read it from the `ca.crt` key of the
  `blanketops-sigstore-roots` ConfigMap, next to the sigstore trust anchors;
- Tekton Chains and the policy controller, for Fulcio and Rekor, get it from a `supply-chain-ca` ConfigMap in
  their namespace;
- Fulcio verifies the CT log, which it submits every certificate to, and SPIRE's discovery;
- External Secrets verifies Vault (`caProvider` on the store), and Vault verifies SPIRE's discovery;
- the CLI verifies Vault and Rekor when it talks to them.

`kubectl exec -n vault vault-0 -c vault -- vault …` still works as before: it runs inside the pod, on loopback.

> **The discovery address is also an identity.** It is the issuer written into every JWT-SVID, and so into
> every signing certificate, and Fulcio, Vault and the admission policies match it exactly. Moving it from
> `http://` to `https://` therefore changes who signed: images signed before the change are no longer admitted
> and have to be built again. The installer restarts SPIRE's server and agent and the store's identity when the
> issuer changes, so that none of them keeps handing out tokens with the old one. After upgrading an existing
> install, run it once end to end.

To use a CA of your own, put its certificate and key in the Secret `cert-manager/supply-chain-ca` (`tls.crt`,
`tls.key`) before installing. To look at what is issued:

```bash
kubectl get clusterissuer supply-chain-ca
kubectl get certificates -A
```

**Re-running it is safe.** What must only be made once is never made again: the keys Fulcio, the CT log and
Rekor sign with, the Merkle trees behind Rekor and the CT log, Vault's unseal key and root token, and the
SonarQube database password. If an
install stops on a timeout, run it again with `--from-step` set to the step it stopped at.

### Checking the install

`supplychain status` reports on everything the installer sets up, at any point during an install or after it:

```bash
./bin/supplychain status
```

```
Secure software supply chain dependencies

Certificates
  ✓ cert-manager                           running (1/1)
  ✓ cert-manager webhook                   running (1/1)
  ✓ cert-manager CA injector               running (1/1)
  ✓ Certificate authority                  ready (ClusterIssuer supply-chain-ca)
  ✓ TLS rekor-system/rekor-server-tls      issued, renews 2026-12-10
  …
SPIRE
  ✓ Server                                 running (1/1)
  …
Credentials
  ✓ Vault                                  running (1/1)
  ✓ Secret store                           logged in (Vault, with a SPIFFE identity)
  …
Everything is running.
```

It covers each workload, grouped as Certificates, Tekton, SPIRE, Sigstore, Ingress, Credentials and Code
analysis; the certificate authority and every TLS certificate issued from it, with the day it is renewed; and
whether the secret store can log in, and how. `✓` is running, `…` is there but not ready yet, and `✗` is missing.

- A Vault that is sealed shows as `starting (0/1)`: it is not ready until it is unsealed.
- SPIRE is reported as not installed, without being counted as a problem, when the signing identity is
  Kubernetes; so is Vault with `--vault-addr` or `--external-secret-store`.
- The command exits with an error when anything that should be there is missing or not ready, so it can gate a
  script: `./bin/supplychain status && kubectl apply -k config/samples`.

## 2. Deploy the operator

The controller's image is built with [ko](https://ko.build): the Go binary on a distroless base, with no
Dockerfile and no container daemon. The build downloads ko itself.

```bash
export IMG=<registry>/supply-chain-controller:<tag>

mage ko:push          # build for linux/amd64 and linux/arm64, push, attach an SPDX SBOM
mage install          # the CRDs
mage deploy           # the controller, running $IMG
```

On a kind cluster nothing has to be pushed. Build the image into an archive and load that:

```bash
export IMG=<registry>/supply-chain-controller:<tag> KIND_CLUSTER=<cluster>

mage ko:build ko:load
mage install deploy
```

`config/manager/manager.yaml` sets `imagePullPolicy: Never`, which is what a loaded image needs; change it to
`IfNotPresent` when the image comes from a registry.

### Where the evidence is stored: immudb

When a build is over, the operator writes its evidence (every signature and attestation record) to
[immudb](https://immudb.io), all of it in one transaction, and only then publishes the build's result. It reads
the server and the login from the Secret `immudb` in the operator's namespace:

```bash
kubectl -n secure-software-supply-chain-system create secret generic immudb \
  --from-literal=IMMUDB_ADDR=<host> --from-literal=IMMUDB_PORT=3322 \
  --from-literal=IMMUDB_USER=<user> --from-literal=IMMUDB_PASSWORD=<password> \
  --from-literal=IMMUDB_DB=securesoftwaresupplychain
```

On a kind cluster, an immudb running in Docker on the same machine is reached at the gateway of the `kind`
network (`docker network inspect kind`, usually `172.18.0.1`), on the port it publishes. Without the Secret, or
when immudb cannot be reached, nothing falls back: the build's result is not published,
`status.evidence.ledgerMessage` of its `ImageBuildResult` says why, and the operator tries again.

The unit tests of `pkg/immudb`, `pkg/evidence` and `pkg/tekton/results` need an immudb at `127.0.0.1:3322`
(override with the same `IMMUDB_*` variables) and fail without one.

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
supplychain secrets set git/ssh-privatekey=@<path-to-private-key> \
                        git/known-hosts=@<file from: ssh-keyscan github.com> \
                        git/ssh-config=@<ssh-client-config>
supplychain secrets set registry/config=@<docker config.json with push access>
supplychain secrets set github/token=@<file holding a GitHub token>

supplychain secrets list                   # which keys are set; never prints a value
supplychain secrets get git/known-hosts    # the value Vault holds for one key
```

These are the store's keys. Each is one secret in Vault under `secret/`, holding a single field named `value`,
and every build asks the store for exactly these:

| Key | What it is |
|---|---|
| `supplychain/git/ssh-privatekey` | An SSH key that can read the repository |
| `supplychain/git/known-hosts` | The git host's keys, for example from `ssh-keyscan github.com` |
| `supplychain/git/ssh-config` | SSH client configuration for the git host |
| `supplychain/registry/config` | A Docker `config.json` with push access: `{"auths":{"https://index.docker.io/v1/":{"auth":"<base64 of user:token>"}}}` |
| `supplychain/github/token` | A token that can manage the repository's webhooks |
| `supplychain/sonarqube/token` | Written for you in phase 4 |

The CLI takes a key without the `supplychain/` they all share. `secrets get` is the same read as Vault's own
client makes, if you would rather look there:

```bash
kubectl exec -n vault vault-0 -c vault -- vault kv get secret/supplychain/git/known-hosts
```

(`vault login` first, inside the pod, with the root token from the `vault-unseal` Secret.)
[`hack/vault-secrets.sh`](../hack/vault-secrets.sh) walks through this phase one step at a time: the store, the
keys, a value going in, and the same value arriving in a build's Secret.

Use a registry access token rather than a password, and a GitHub fine-grained token limited to the repository.
A GitHub deploy key belongs to exactly one repository; there is one SSH key for every `SupplyChain`, so for more
than one repository use a machine user's key.

**Rotating a credential** is the same command again. `set` changes the keys you name and leaves the rest, and
External Secrets re-reads every secret each minute, so the new value reaches the builds without anything being
deleted or restarted.

### How the store is set up

Installer steps do this, and all can be run again safely.

`Vault` starts one Vault server with its data on a volume, and initialises and unseals it.

`Secret Store` then enables a key-value engine at `secret/` if there is none, writes a policy that can **read**
`secret/supplychain/*` and nothing else, gives exactly one identity a login with that policy, and creates the
`ClusterSecretStore` named `secure-software-supply-chain-store`, waiting until it has logged in.

The operator never talks to Vault and has no Vault credential. It only creates `ExternalSecret` objects that
point at the store. Neither the store nor anything else in the cluster holds a lasting Vault credential for
reading secrets; which short-lived one is used follows the signing identity.

#### With `--signing-identity spiffe`: a SPIFFE identity

The store logs in the way the SPIFFE project describes in
[Using SPIRE JWT-SVIDs to authenticate to Vault](https://spiffe.io/docs/latest/keyless/vault/readme/): Vault
trusts SPIRE, and a workload proves who it is with nothing but the JWT-SVID SPIRE issued it.

```
SPIRE ── issues ──► JWT-SVID for spiffe://<your-domain>/ns/vault/sa/supply-chain-secrets   (audience "vault", 10 min)
                        │  kept current in the Secret vault/supply-chain-vault-jwt
                        ▼
External Secrets ── presents it ──► Vault auth/jwt
                                      ├─ signature checked against SPIRE's OIDC discovery keys
                                      ├─ issuer, audience and subject must match the role
                                      └─ token for the policy supply-chain-read, valid 10 min
```

- **SPIRE** has one entry for the identity, for the ServiceAccount `vault/supply-chain-secrets` on an attested
  node. No other pod can obtain it. The `Secret Store Identity` step creates it with the rest of the SPIRE
  identities.
- **Vault** has JWT auth at `auth/jwt` pointed at SPIRE's OIDC discovery endpoint, which it verifies against
  the secure software supply chain's CA, and one role:

  ```bash
  vault write auth/jwt/config oidc_discovery_url=<SPIRE OIDC discovery> bound_issuer=<the same> \
      oidc_discovery_ca_pem=@<the CA>
  vault write auth/jwt/role/supply-chain role_type=jwt user_claim=sub \
      bound_audiences=vault \
      bound_subject=spiffe://<your-domain>/ns/vault/sa/supply-chain-secrets \
      token_policies=supply-chain-read token_ttl=10m
  ```

  The installer does this for you. A Kubernetes ServiceAccount token is refused at this login, and the
  Kubernetes login an earlier install may have made is removed.
- **External Secrets cannot ask the SPIFFE Workload API for a JWT-SVID itself**; it reads the JWT it presents
  from a Secret. The Deployment `vault/supply-chain-svid` is the bridge: it runs as that ServiceAccount, keeps a
  current JWT-SVID with [spiffe-helper](https://github.com/spiffe/spiffe-helper), and copies it into the Secret
  `supply-chain-vault-jwt`. It may write that one Secret and nothing else. The JWT is valid for ten minutes and
  replaced after five.

Taking the identity away ends the access: delete the SPIRE entry
(`kubectl delete clusterstaticentry supply-chain-secrets`) and within ten minutes Vault accepts nothing.

The store is this one, also in
[`config/samples/externalsecrets_v1_clustersecretstore_vault_spiffe.yaml`](../config/samples/externalsecrets_v1_clustersecretstore_vault_spiffe.yaml):

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: secure-software-supply-chain-store
spec:
  provider:
    vault:
      server: https://vault.vault.svc.cluster.local:8200
      path: secret              # the key-value (version 2) engine
      version: v2
      caProvider:               # Vault's certificate comes from the secure software supply chain's CA
        type: ConfigMap
        name: supply-chain-ca
        key: ca.crt
        namespace: vault
      auth:
        jwt:                    # the JWT is a SPIFFE JWT-SVID, valid for minutes
          path: jwt
          role: supply-chain
          secretRef:
            name: supply-chain-vault-jwt
            namespace: vault
            key: jwt
```

#### With `--signing-identity kubernetes`: a ServiceAccount

Without SPIRE, Vault's Kubernetes auth is enabled, with a role bound to the single ServiceAccount
`vault/supply-chain-secrets`. External Secrets asks the API server for a short-lived token for it, and Vault asks
the API server whether the token is genuine. The store is
[`config/samples/externalsecrets_v1_clustersecretstore_vault.yaml`](../config/samples/externalsecrets_v1_clustersecretstore_vault.yaml):

```yaml
      auth:
        kubernetes:
          mountPath: kubernetes
          role: supply-chain
          serviceAccountRef:
            name: supply-chain-secrets
            namespace: vault
```

Either way, an `ExternalSecret` the operator creates asks the store for one key at a time, for example the SSH
key:

```yaml
spec:
  refreshInterval: 1m
  secretStoreRef: { name: secure-software-supply-chain-store, kind: ClusterSecretStore }
  data:
  - secretKey: id_rsa
    remoteRef: { key: supplychain/git/ssh-privatekey, property: value }
```

> **Before production.** Two things here are set up for a self-contained demonstration, and are yours to
> change: Vault runs as a single server on a file volume, and its unseal key is kept next to it, as the next
> note says.

> **Vault's own keys are in the cluster.** Vault seals itself whenever its pod restarts, and a sidecar unseals
> it with a key the installer keeps in the `vault-unseal` Secret, next to Vault's root token. That is what makes
> the install self-contained, and it means anyone who can read Secrets in the `vault` namespace can open Vault.
> It is right for a demonstration and wrong for production: there, use one of Vault's
> [auto-unseal](https://developer.hashicorp.com/vault/docs/concepts/seal#auto-unseal) mechanisms, remove the
> Secret, and revoke the root token.

### Using a Vault you already have

Point the installer at it and it runs none of its own. It still sets up the store:

```bash
export VAULT_ADDR=<address of your Vault>
vault login                                   # or export VAULT_TOKEN; the CLI reads ~/.vault-token

supplychain install --vault-addr "$VAULT_ADDR" --webhook-host <host> ...
supplychain secrets set git/ssh-privatekey=@<file> ...      # with VAULT_ADDR still set
```

`--vault-addr` is the address **the cluster** reaches Vault at. `VAULT_ADDR` is the address the CLI uses, when
that is a different one. The token needs the right to enable an auth method and to write one policy and one
role; it is used by the CLI and stored nowhere in the cluster.

A Vault outside the cluster can reach neither this cluster's API server nor SPIRE's discovery endpoint, which
is only served inside the cluster. So the login is different from the built-in Vault's, whichever signing
identity is used. The installer gives Vault the cluster's public token-signing keys, in a JWT
auth method at `auth/supply-chain`, and Vault checks tokens against them itself. It accepts only tokens from
this cluster's issuer, made for the audience `vault`, for the one ServiceAccount. Vault never has to reach the
cluster. If the cluster's signing keys are rotated, run the `Secret Store` step again.

An existing key-value engine at `secret/` is used as it is, provided it is version 2. Nothing else in your
Vault is changed: an auth method of that name that is not JWT is left alone, and the step stops.

### Using a secret store of your own

Vault is what the installer sets up, not something the operator depends on. The operator reads through
External Secrets, so any [provider](https://external-secrets.io/latest/introduction/stability-support/) it
supports will do: AWS Secrets Manager, Google Secret Manager, Azure Key Vault, an existing Vault, and so on.

The operator owns the `ExternalSecret` objects: it creates them for each build and puts them back if they are
changed, so what they ask for is fixed. Your store has to answer to the same names:

- a `ClusterSecretStore` called **`secure-software-supply-chain-store`**;
- the six keys in the table above, under the same names (`supplychain/git/ssh-privatekey` and so on);
- each holding its value in a field named `value`. The operator asks for that field as a `property` of the
  secret, so in a store that keeps one string per secret, the string is the JSON object `{"value": "…"}`.

[`config/samples/externalsecrets_v1_clustersecretstore_aws.yaml`](../config/samples/externalsecrets_v1_clustersecretstore_aws.yaml)
is an example for AWS Secrets Manager, with the same names. It is a starting point and has not been run as part
of this project's tests.

Install without Vault, and have the SonarQube bootstrap hand you the token instead of writing it to Vault:

```bash
supplychain install --external-secret-store --webhook-host <host> ...
supplychain init-sonarqube --new-password '<password>' --token-file <file>
# then store the contents of <file> as supplychain/sonarqube/token
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

The samples go in the operator's own namespace, `secure-software-supply-chain-system`, the way Argo CD keeps its
Applications in `argocd`: a SupplyChain's builds, their ServiceAccount, the credentials they read and its
EventListener all live there, and nothing of ours is left in `default`. The operator copies the sigstore trust
anchors (`blanketops-sigstore-roots`) into the namespace from the installer's copy in `tekton-chains`, keeps the
copy in step, and removes it with the last SupplyChain or SupplyChainPolicy using it. A SupplyChain placed in any
other namespace gets the same.

```bash
kubectl get supplychain,supplychainpolicy,githubwebhook -n secure-software-supply-chain-system
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
  `http://supplychain.localhost:8888/sonarqube/`. To reach them from your other devices, publish them
  tailnet-only, never through Funnel: see [Reaching the UIs](access.md).
- Set a webhook secret (`spec.webhookSecretRef` on the `GitHubWebhook`) so that only GitHub's deliveries start
  builds.
- `tailscale funnel reset` takes the hostname off the internet again.

> **Branch names containing `/`** cannot trigger a build yet: the branch is part of the build's name.

## 7. Check it with one build

Push a commit, or start a build by hand (see [Trigger a build by hand](usage.md#trigger-a-build-by-hand)), then:

```bash
kubectl get imagebuilds -n secure-software-supply-chain-system -w           # Pending -> Running -> Succeeded
kubectl get imagesignatures,imagebuildresults -n secure-software-supply-chain-system
```

A finished build has an `ImageSignature` that is `Signed`, with the Rekor index of its signature, and an
`ImageBuildResult` whose evidence lists the build's and Chains' signatures and attestations. Run the image in a
namespace labelled `policy.sigstore.dev/include=true`: it is admitted, and an image this pipeline did not build
is refused.
