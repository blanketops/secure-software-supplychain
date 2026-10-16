# Reaching the UIs

[← Back to the README](../README.md)

The stack's UIs and APIs run inside the cluster with no public address. They are reached through the
[Tailscale](https://tailscale.com) name of the machine that runs the cluster. One entry is public: the GitHub
webhook, through Tailscale Funnel (see [Installation, phase 6](installation.md#6-make-the-webhook-reachable-tailscale-funnel)).
Every other entry is served **tailnet-only**, so it answers on devices signed in to your tailnet and nowhere
else. Some stay on the machine itself, because they have no login and can change what the cluster trusts.

## Links

These are the links of the reference installation, on `pop-os.tailf8145.ts.net`. On your own machine,
substitute its name (`tailscale status --json | jq -r '.Self.DNSName'`).

| Link | What | Reach | Login |
|---|---|---|---|
| `https://pop-os.tailf8145.ts.net/` | GitHub push webhook, to the EventListener | Public (Funnel) | GitHub's signature on each delivery |
| `https://pop-os.tailf8145.ts.net:8002/` | The [observer](usage.md#the-observer): supply chains, builds, signatures, the transparency log, permissions, admission policies | Tailnet | None; it only reads (see below) |
| `https://pop-os.tailf8145.ts.net:9097/` | Tekton Dashboard: PipelineRuns and their logs | Tailnet | None; installed `--read-only=true` |
| `https://pop-os.tailf8145.ts.net:9000/sonarqube/` | SonarQube | Tailnet | SonarQube's own |
| `https://pop-os.tailf8145.ts.net:3443/api/v1/log` | Rekor API, the transparency log | Tailnet | None; see below |
| `https://pop-os.tailf8145.ts.net:8081/` | Argo CD, in the verify-only read cluster | Tailnet | Argo CD's own (`admin`); GitHub sign-in through `hack/argocd-github-sso.sh` in infrastructure-gitops |
| `https://pop-os.tailf8145.ts.net:8443/` | `for-kaniko-app`, the sample workload in the read cluster | Tailnet | None; a public demo page |
| `http://127.0.0.1:3000/` | Tornjak, the SPIFFE UI | This machine only | None; never publish it (see below) |

Argo CD and the sample workload belong to the two-cluster setup, in which a second cluster only verifies
images. That setup lives in the sibling repository
[infrastructure-gitops](https://github.com/blanketops/infrastructure-gitops). Its
`hack/tailnet-links.sh` creates every link above and `hack/tailnet-links.sh check` prints them with the
status each answers with now.

## How a link is made

Each tailnet link is a `kubectl port-forward` to a Service, bound to `127.0.0.1` and published by
`tailscale serve` on a port of its own:

```bash
kubectl port-forward --address 127.0.0.1 -n tekton-pipelines svc/tekton-dashboard 9097:9097
tailscale serve --bg --https=9097 http://127.0.0.1:9097      # tailnet-only, with a valid certificate
tailscale serve status                                        # every entry and whether it is public
```

`tailscale serve` changes need no root once you are the Tailscale operator: `sudo tailscale set --operator=$USER`,
once. Without `funnel`, an entry is never reachable from the internet; check that `tailscale serve status` lists
only the webhook as `(Funnel on)`.

A port-forward has to outlive the terminal it was started from and the pod it points at. Run each one as a
user systemd unit with `Restart=always`. That alone is not enough: when the pod behind it is replaced,
`kubectl port-forward` can keep running and forward nothing, so systemd never restarts it. Run it under a
watchdog that exits once the local port stops answering, as `hack/tailnet-links.sh` does with `kpf-watch`.
The installation's Tekton Dashboard link came back about 15 seconds after its pod was deleted.

## What is safe to publish, and what is not

A link without a login is safe on the tailnet only if it cannot change anything that matters. A tailnet-only
link is not private to you alone: any page open in a browser on one of your tailnet devices can send requests
to it.

- **The observer** forwards only the Kubernetes reads its page makes and refuses everything else, Secrets and
  every write included. Its server holds your kubeconfig's access through `kubectl proxy`, so this guard is what
  makes publishing it safe. Run it pinned to one cluster, without opening a browser:
  `supplychain observe --context <context> --no-browser`.
- **The Tekton Dashboard** is installed read-only, so it shows runs and logs and cannot start or delete them.
- **Rekor** is the transparency log. Reading it is the point. Its write API answers too, because verification
  looks entries up with POST requests. Anyone who can reach it can add an entry, but no entry makes an image
  trusted. Keep it off the public Funnel hostname.
- **Tornjak** has no login, and its API creates and deletes SPIRE registration entries while allowing every
  origin (`Access-Control-Allow-Origin: *`). A registration entry is how a workload gets a SPIFFE identity, and
  with `--signing-identity spiffe` that identity is what signs images. Published without a login, any page open
  in a browser on a tailnet device could register an identity. Keep it on the machine
  (`kubectl port-forward -n spire-server svc/tornjak 3000:3000 10000:10000`, then `http://localhost:3000`). Publish it
  only behind an authenticating proxy, as [Usage](usage.md#the-spiffe-ui-tornjak) says.

## When the webhook stops arriving

GitHub's delivery log (`gh api repos/<owner>/<repo>/hooks/<id>/deliveries`) shows a lost push as
`500 ... EOF`. Check each hop:

```bash
# 1. the bridge and ingress on this machine: expect 202
curl -X POST -H 'Host: <webhook-host>' -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8888/

# 2. the public path, through each of Funnel's relays: expect 202 from all of them
for ip in $(curl -s -H 'accept: application/dns-json' \
    'https://1.1.1.1/dns-query?name=<webhook-host>&type=A' | jq -r '.Answer[].data'); do
  curl -s -o /dev/null -w "$ip %{http_code}\n" --resolve <webhook-host>:443:$ip \
    -X POST -H 'Content-Type: application/json' -d '{}' https://<webhook-host>/
done
```

Test the public path through the relay addresses. On the machine itself, MagicDNS resolves the name to the
tailnet address, which answers even when Funnel is down. A POST without GitHub's signature is accepted (202)
and then dropped by the EventListener's interceptor, so these checks start no build.

Hop 1 answering and some relays failing the TLS handshake (`000`) means Funnel lost its connections after a
network change or on a lossy uplink; `tailscale status --json | jq .Health` then usually reports a connectivity
problem. `sudo systemctl restart tailscaled` restores it, and the serve and Funnel configuration survive the
restart. Push again afterwards; GitHub does not retry a failed delivery on its own.
