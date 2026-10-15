# Baking in Tornjak as the SPIFFE UI — design & plan

Status: IMPLEMENTED (Tornjak v1.4.2 sidecars, internal-only). This records the
design; the manifests, installer behaviour, tests and docs now match it. See
`dependencies/spire/release/tornjak.yaml`, the `tornjak-backend`/
`tornjak-frontend` sidecars in `release.yaml`, `TestTornjakSidecar`, and the
Tornjak sections of `docs/concepts.md` and `docs/usage.md`.

## Goal

Give operators a SPIFFE management UI (Tornjak) to see and manage the SPIRE
entries this stack creates — only under `--signing-identity spiffe`, where
SPIRE is installed at all.

## What exists today (ground truth)

- SPIRE server is a **StatefulSet** `spire-server` in namespace `spire-server`
  (upstream Helm chart v0.1.0, SPIRE 1.15.3). Containers: `spire-server`
  (`ghcr.io/spiffe/spire-server:1.15.3`) + `spire-controller-manager`.
- The pod already has a shared `emptyDir` volume **`spire-server-socket`**
  mounted at **`/tmp/spire-server/private`** on both containers — this is the
  SPIRE server's API socket directory. A Tornjak backend sidecar mounts the
  same volume to reach the server. `shareProcessNamespace: true` is already set.
- Server config (ConfigMap `spire-server`) binds 8080 (healthz) and 8081
  (grpc); `trust_domain` is the placeholder `trust-domain.placeholder.invalid`,
  substituted at install time from `--trust-domain`.
- Tornjak is NOT deployed. The only trace is a stray
  `checksum/configTornjak` annotation on the server pod template — a disabled
  remnant of the Helm chart's tornjak support. No container, config, or service.
- UI convention: workload → `Service` → `Ingress` on `UI_HOST` (the `--ui-host`
  flag), explicitly kept off the public webhook host. See
  `dependencies/ingress/routes/tekton-dashboard.yaml`.
- Image convention: every image pinned by digest,
  `registry/name:tag@sha256:...` (see `dependencies/*`).
- Installer: SPIRE is applied in the `SPIRE` step, gated by `onlyForSPIFFE`
  (`cmd/cli/installer/installer.go`); steps apply manifests + a readiness wait.

## Decision (agreed)

- **Shape: sidecar.** Tornjak backend + frontend as containers in the existing
  `spire-server` StatefulSet. Rationale: the server API socket is already a
  shared in-pod volume; this is exactly what the chart's tornjak support
  assumes; no cross-pod auth to the server API to invent.
- **Exposure: internal-only (to start).** A `Service` only; reach it with
  `kubectl port-forward`. NO ingress yet. Rationale: Tornjak's API can create
  and delete SPIFFE identities; its default build is unauthenticated. Putting a
  privileged, unauthenticated management surface on `--ui-host` is a deliberate
  security decision we should not make by default. Ingress can be added later
  behind auth.

## Work breakdown (when we implement)

1. **Server config: enable the admin/Tornjak API.**
   The Tornjak backend talks to the SPIRE server. Enable the server's admin API
   over the shared UDS (or Tornjak's own gRPC to the server socket). Concretely,
   in the `spire-server` ConfigMap add the admin API / `tornjak` server plugin
   block pointing at `/tmp/spire-server/private/api.sock`. This is the one real
   config change beyond adding containers; verify against the Tornjak version's
   required server config.

2. **Add sidecars to the `spire-server` StatefulSet.**
   - `tornjak-backend` — mounts `spire-server-socket` at
     `/tmp/spire-server/private`; serves the Tornjak API (default :10000).
   - `tornjak-frontend` — serves the React UI (default :3000), pointed at the
     backend. (Can be one combined image; pick per the release.)
   - Pin both by digest: `ghcr.io/spiffe/tornjak-backend@sha256:...` and
     `...-frontend@sha256:...`. Resolve a specific release tag + digest at
     implementation time.
   - Add a `tornjak-config` ConfigMap (backend server-info / SPIRE socket path).
   - Drop the stale `checksum/configTornjak` annotation or replace it with a
     real checksum of the new config.

3. **Service.** `tornjak` Service in `spire-server` exposing the frontend (and
   backend if accessed directly). No ingress.

4. **Installer wiring.** Smallest change: tornjak ships inside the SPIRE release
   manifests, so it is applied by the existing `SPIRE` step and inherits
   `onlyForSPIFFE` for free — no new step needed. Add a readiness note. If we
   want it toggleable, a `--tornjak=false` opt-out on the SPIRE step; otherwise
   it is simply part of SPIRE under SPIFFE.

5. **Tests.** Mirror the existing SPIRE manifest tests
   (`cmd/cli/installer/*_test.go` assert manifest shape): assert the tornjak
   containers/Service exist in the SPIRE step and that they are absent /
   skipped for the Kubernetes identity (non-SPIFFE).

6. **Docs.** `docs/concepts.md` (what Tornjak is, why internal-only) +
   `docs/usage.md` (the `kubectl port-forward -n spire-server svc/tornjak ...`
   command to open it). Note the security posture explicitly.

## Open questions to resolve at implementation time

- **Tornjak release + digests.** Pick a pinned version; confirm backend/frontend
  split vs. combined image for that release.
- **Server config specifics.** The exact admin-API / tornjak plugin block the
  chosen Tornjak version needs, validated against SPIRE 1.15.3.
- **Auth, if we ever expose it.** Internal-only avoids this now; an ingress
  later needs auth (oauth2-proxy / mTLS) in front — do not ingress it raw.

## Explicitly out of scope for the first cut

- Ingress on `--ui-host` (deferred until auth is decided).
- Federation/management features beyond read + basic entry management.
- Changing the non-SPIFFE path at all (Tornjak only exists under SPIFFE).
