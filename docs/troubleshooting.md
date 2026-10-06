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
repository. Remember the synced Secret has to be deleted after the store changes.

**A policy is `Ready=False`.** The reason says which input is missing: `AuthorizationDenied`,
`SupplyChainNotFound`, `SigningDisabled`, `TrustAnchorsNotFound`, `TrustAnchorsInvalid`,
`PolicyControllerNotInstalled` or `ApplyFailed`.
