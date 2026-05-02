# Demo Videos

This directory contains automated demo scripts and recordings for the
secure-software-supply-chain operator.

## Videos

| Demo | Description | Script |
|------|-------------|--------|
| `full-pipeline.mp4` | End-to-end: GitHub push → ImageBuild → PipelineRun → Signed image | `scripts/full-pipeline.sh` |
| `supplychain-setup.mp4` | Fresh cluster setup: install deps, apply SupplyChain CR | `scripts/supplychain-setup.sh` |
| `webhook-automation.mp4` | GitHubWebhook CR: auto-register → push → pipeline fires | `scripts/webhook-automation.sh` |
| `signing-verify.mp4` | Verify signed image with cosign + Rekor transparency log | `scripts/signing-verify.sh` |

## Recording

Videos are recorded using [vhs](https://github.com/charmbracelet/vhs) — a terminal recorder
that produces MP4s from `.tape` files. Install:

```bash
go install github.com/charmbracelet/vhs@latest
```

Record a demo:

```bash
vhs scripts/full-pipeline.tape
```

## Scripts

- `scripts/full-pipeline.tape` — vhs tape for full pipeline demo
- `scripts/supplychain-setup.tape` — vhs tape for setup demo
- `scripts/webhook-automation.tape` — vhs tape for webhook demo
- `scripts/signing-verify.tape` — vhs tape for signing verification demo
