# Troubleshooting

[← Back to the README](../README.md)

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
repository. Check what is set with `supplychain secrets list`, and replace the key with
`supplychain secrets set git/ssh-privatekey=@<file>`; the build's Secret follows within a minute.

**A `GitHubWebhook` stays `Failed` with "GitHub API returned 401".** GitHub refused the token in the store.
Replace it with `supplychain secrets set github/token=@<file>`. The operator tries again every two minutes, so
the webhook registers by itself once the new token has synced.

**A build waits for its secrets and never starts.** The `ExternalSecret` objects cannot be synced. Look at the
store first:

```bash
kubectl get clustersecretstore secure-software-supply-chain-store
kubectl get pods -n vault
```

A store that is not `Valid` usually means Vault is sealed or still starting: `vault-0` shows `1/2` until its
sidecar has unsealed it, which takes a few seconds after a restart. If it stays sealed, the `vault-unseal` Secret
is missing. A store that is `Valid` with an `ExternalSecret` in `SecretSyncedError` means a key is missing in
Vault; `supplychain secrets list` shows which.

With SPIFFE identities the store presents a JWT-SVID, so also check where that comes from:

```bash
kubectl get pods -n vault -l app.kubernetes.io/name=supply-chain-svid     # 2/2 when a current JWT is published
kubectl logs -n vault deploy/supply-chain-svid -c svid --tail=5           # "JWT SVID updated"
kubectl get clusterstaticentry supply-chain-secrets                       # the identity SPIRE may issue
```

`1/2` means SPIRE has not issued the identity: the entry is missing, or the SPIRE agent is not running on the
node. Re-run `supplychain install --only-step "SPIRE Identities"` and then `--only-step "Secret Store"` with the
same `--signing-identity` and `--trust-domain` as the install. If SPIRE itself was reinstalled its signing keys
changed, and the same two steps make Vault trust the new ones.

**Deploying a signed image fails with "failed calling webhook ... context deadline exceeded".** The policy
controller reads the image's signatures and attestations from the registry, once for each of the four policies,
and the API server gives it ten seconds. On a slow connection to the registry that is not always enough. The
webhook fails closed, so nothing unverified is admitted; apply the workload again.

**A build fails at `sign-image-cosign` with a registry error after "tlog entry created".** The signature was
logged in Rekor but could not be stored next to the image, usually a network failure talking to the registry.
The image is left without the build's signature and admission will refuse it. Run the build again.

**A policy is `Ready=False`.** The reason says which input is missing: `AuthorizationDenied`,
`SupplyChainNotFound`, `SigningDisabled`, `TrustAnchorsNotFound`, `TrustAnchorsInvalid`,
`PolicyControllerNotInstalled` or `ApplyFailed`.
