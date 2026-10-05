/*
Copyright 2026 The BlanketOps Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package pipeline

import (
	"time"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/authz"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

const (
	stepGitClone           = "git-clone"
	stepAuthFulcio         = "authentication-fulcio"
	stepSonarQube          = "code-scan-sonarqube"
	stepBuildImage         = "build-image-buildah"
	stepPushImage          = "push-image-docker"
	stepTrivy              = "vulnerability-scan-trivy"
	stepSign               = "sign-image-cosign"
	stepAttest             = "attest-image-rekor-fulcio"
	stepVerify             = "verify-image-policy"
	cosignImage            = "gcr.io/projectsigstore/cosign:v2.2.3"
	sigstoreRootsMountPath = "/etc/sigstore"
	// Steps of one task share /workspace.
	authorizationPredicatePath = "/workspace/authorization-predicate.json"
	authorizationPolicyPath    = "/workspace/authorization-policy.cue"
	// imageArchive is the build output in the shared workspace.
	imageArchive          = "image.tar"
	workspaceShared       = "shared-data"
	workspaceSSHCreds     = "ssh-creds"
	workspaceDockerConfig = "dockerconfig"
	// workspaceTrivyCache removed — Trivy DB is now baked into the scanner image.
	// See dependencies/tekton/task/trivy-db/Dockerfile.
)

func BuildPipelineRun(
	name, namespace string,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
	imageRef string,
	sigCtx *signing.RunSigningContext,
) *tektonv1.PipelineRun {
	sa := sc.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}

	// ── Workspace bindings ─────────────────────────────────────────────────
	//
	// workspaceShared       — ephemeral VolumeClaimTemplate per run.
	//                         Holds cloned source, build artifacts, and
	//                         the Trivy SARIF report. Deleted after the run.
	// workspaceSSHCreds     — git SSH key secret, read-only.
	// workspaceDockerConfig — registry auth secret, read-only.
	//
	// Note: Trivy no longer needs a cache workspace. The vulnerability DB
	// is pre-baked into docker.io/nkanyezisolutions/trivy-db:latest at
	// image build time. Rebuild that image periodically to refresh the DB.
	workspaces := []tektonv1.WorkspaceBinding{
		{
			Name: workspaceShared,
			VolumeClaimTemplate: &corev1.PersistentVolumeClaim{
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{
						corev1.ReadWriteOnce,
					},
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("2Gi"),
						},
					},
				},
			},
		},
		{
			Name: workspaceSSHCreds,
			Secret: &corev1.SecretVolumeSource{
				SecretName: sc.Spec.Image.CloneSecretRef,
			},
		},
		{
			Name: workspaceDockerConfig,
			Secret: &corev1.SecretVolumeSource{
				SecretName: sc.Spec.Image.RegistrySecretRef,
			},
		},
	}

	return &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: tektonv1.PipelineRunSpec{
			TaskRunTemplate: tektonv1.PipelineTaskRunTemplate{
				ServiceAccountName: sa,
			},
			Workspaces: workspaces,
			PipelineSpec: &tektonv1.PipelineSpec{
				Workspaces: []tektonv1.PipelineWorkspaceDeclaration{
					{Name: workspaceShared},
					{Name: workspaceSSHCreds},
					{Name: workspaceDockerConfig},
				},
				Params: []tektonv1.ParamSpec{
					{Name: "image-ref", Type: tektonv1.ParamTypeString},
					{Name: "git-url", Type: tektonv1.ParamTypeString},
					{Name: "git-revision", Type: tektonv1.ParamTypeString},
				},
				Tasks:   buildTaskList(sc, ib, imageRef, sigCtx),
				Results: buildResults(sc, sigCtx != nil),
			},
			Params: tektonv1.Params{
				{
					Name: "image-ref",
					Value: tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: imageRef,
					},
				},
				{
					Name: "git-url",
					Value: tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: ib.Spec.GitRef.URL,
					},
				},
				{
					Name: "git-revision",
					Value: tektonv1.ParamValue{
						Type:      tektonv1.ParamTypeString,
						StringVal: ib.Spec.GitRef.Revision,
					},
				},
			},
		},
	}
}

// ── buildResults update ────────────────────────────────────────────────────
// Replace the REKOR_LOG_INDEX entry in buildResults:

func buildResults(sc *supplyv1alpha1.SupplyChain, verified bool) []tektonv1.PipelineResult {
	results := []tektonv1.PipelineResult{
		{Name: "commit", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepGitClone + ".results.commit)"}},
		{Name: "committer-date", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepGitClone + ".results.committer-date)"}},
		{Name: "url", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepGitClone + ".results.url)"}},
		// The digest the registry serves, from the push — not the digest of the
		// local build archive, which changes when the image is pushed.
		{Name: "IMAGE_DIGEST", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepPushImage + ".results.IMAGE_DIGEST)"}},
		{Name: "IMAGE_URL", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepPushImage + ".results.IMAGE_URL)"}},
	}

	if sc.Spec.Steps.Trivy {
		results = append(results,
			tektonv1.PipelineResult{Name: "TRIVY_SCAN_SUMMARY", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepTrivy + ".results.TRIVY_SCAN_SUMMARY)"}},
			tektonv1.PipelineResult{Name: "TRIVY_CRITICAL_COUNT", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepTrivy + ".results.TRIVY_CRITICAL_COUNT)"}},
			tektonv1.PipelineResult{Name: "TRIVY_HIGH_COUNT", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepTrivy + ".results.TRIVY_HIGH_COUNT)"}},
			tektonv1.PipelineResult{Name: "TRIVY_TOTAL_COUNT", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepTrivy + ".results.TRIVY_TOTAL_COUNT)"}},
			tektonv1.PipelineResult{Name: "TRIVY_SARIF_PATH", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepTrivy + ".results.TRIVY_SARIF_PATH)"}},
		)
	}

	// Reported by the verify task, which only runs for a signed build.
	if sc.Spec.Steps.Sign && verified {
		results = append(results,
			tektonv1.PipelineResult{Name: "POLICY_VERIFICATION", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepVerify + ".results.POLICY_VERIFICATION)"}},
			tektonv1.PipelineResult{Name: "VERIFIED_SIGNER", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepVerify + ".results.VERIFIED_SIGNER)"}},
		)
	}

	// if sc.Spec.Steps.SonarQube != nil {
	// 	results = append(results,
	// 		tektonv1.PipelineResult{Name: "SONAR_GATE_STATUS", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepSonarQube + ".results.GATE_STATUS)"}},
	// 	)
	// }

	return results
}

func buildTaskList(
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
	imageRef string,
	sigCtx *signing.RunSigningContext,
) []tektonv1.PipelineTask {
	tasks := []tektonv1.PipelineTask{}

	// Step 1: git-clone — fetch source
	tasks = append(tasks, gitCloneTask())
	last := stepGitClone

	// Step 2: auth-fulcio — obtain CA cert as init, before anything else
	// Must be early so signing credentials are warm and ready
	if sc.Spec.Steps.Sign {
		tasks = append(tasks, authFulcioTask(sc, last))
		last = stepAuthFulcio
	}

	// Step 3: sonarqube — scan source code quality before build
	// Fail fast on code quality — no point building dirty code
	if sc.Spec.Steps.SonarQube != nil {
		tasks = append(tasks, sonarQubeTask(sc, last))
		last = stepSonarQube
	}

	// Step 4: build image (Buildah) — source is clean, now build
	tasks = append(tasks, buildImageTask(imageRef, last))
	last = stepBuildImage

	// Step 5: trivy — scan the build archive before anything is published.
	// The push step copies that same archive to the registry, so what is
	// scanned is what will run; scanning first means an image that fails the
	// gate never reaches the registry.
	// Uses a custom image with the vulnerability DB pre-baked — no downloads.
	if sc.Spec.Steps.Trivy {
		tasks = append(tasks, trivyTask(last))
		last = stepTrivy
	}

	// Step 6: push image (Skopeo) — only what passed the scan. The push also
	// yields the digest the registry serves, which is what gets signed.
	tasks = append(tasks, pushImageTask(imageRef, last))
	last = stepPushImage

	// Step 7: sign (Cosign + Fulcio) — image is clean, now sign it
	// Must sign before attesting — you attest to a signed image
	if sc.Spec.Steps.Sign {
		tasks = append(tasks, signTask(sc, imageRef, last, sigCtx))
		last = stepSign
	}

	// Step 8: attest (Rekor) — record attestation of the signed image
	// Rekor logs the signature, not the raw image — sign must come first
	if sc.Spec.Steps.Attest {
		tasks = append(tasks, attestTask(imageRef, last))
		last = stepAttest
	}

	// Step 9: verify — check the published image the way admission will.
	// A build only succeeds if what it produced can actually be deployed.
	if sc.Spec.Steps.Sign && sigCtx != nil {
		tasks = append(tasks, verifyTask(sc, imageRef, last))
	}

	return tasks
}

func gitCloneTask() tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:    stepGitClone,
		TaskRef: &tektonv1.TaskRef{Name: "git-clone"},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "output", Workspace: workspaceShared},
			{Name: "ssh-directory", Workspace: workspaceSSHCreds},
		},
		Params: tektonv1.Params{
			{
				Name: "url",
				Value: tektonv1.ParamValue{
					Type:      tektonv1.ParamTypeString,
					StringVal: "$(params.git-url)",
				},
			},
			{
				Name: "revision",
				Value: tektonv1.ParamValue{
					Type:      tektonv1.ParamTypeString,
					StringVal: "$(params.git-revision)",
				},
			},
		},
	}
}

func authFulcioTask(sc *supplyv1alpha1.SupplyChain, runAfter string) tektonv1.PipelineTask {
	fulcio := signing.EndpointsFor(sc).FulcioURL

	return tektonv1.PipelineTask{
		Name:     stepAuthFulcio,
		RunAfter: after(runAfter),
		TaskSpec: &tektonv1.EmbeddedTask{
			TaskSpec: tektonv1.TaskSpec{
				Params: []tektonv1.ParamSpec{
					{Name: "FULCIO_URL", Type: tektonv1.ParamTypeString},
				},
				Volumes: []corev1.Volume{
					{
						Name: "oidc-info",
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								Sources: []corev1.VolumeProjection{
									{
										ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
											Path:              "oidc-token",
											ExpirationSeconds: int64Ptr(600),
											Audience:          "sigstore",
										},
									},
								},
							},
						},
					},
				},
				Steps: []tektonv1.Step{
					{
						Name:  "verify-fulcio",
						Image: "curlimages/curl:latest",
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "oidc-info",
								MountPath: "/var/run/sigstore/cosign",
							},
						},
						Script: `#!/bin/sh
set -e
TOKEN=$(cat /var/run/sigstore/cosign/oidc-token)
if [ -z "$TOKEN" ]; then
  echo "ERROR: OIDC token is empty"
  exit 1
fi
echo "OIDC token acquired successfully"
echo "Verifying Fulcio endpoint: $(params.FULCIO_URL)"
curl -sf $(params.FULCIO_URL)/api/v1/rootCert > /dev/null
echo "Fulcio reachable and ready"
`,
					},
				},
			},
		},
		Params: tektonv1.Params{
			{Name: "FULCIO_URL", Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fulcio,
			}},
		},
	}
}

func sonarQubeTask(sc *supplyv1alpha1.SupplyChain, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepSonarQube,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "sonarqube-scanner"},
		Params: tektonv1.Params{
			{Name: "SONAR_HOST_URL", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sc.Spec.Steps.SonarQube.ServerURL}},
			{Name: "SONAR_PROJECT_KEY", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sc.Spec.Steps.SonarQube.ProjectKey}},
			{Name: "SONAR_TOKEN_SECRET", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sc.Spec.Steps.SonarQube.TokenSecretRef}},
		},
	}
}

func buildImageTask(imageRef, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepBuildImage,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "buildah"},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "source", Workspace: workspaceShared},
			{Name: "dockerconfig", Workspace: workspaceDockerConfig},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "DOCKERFILE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "./Dockerfile"}},
			{Name: "CONTEXT", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "."}},
		},
	}
}

func pushImageTask(imageRef, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepPushImage,
		RunAfter: after(runAfter),
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "source", Workspace: workspaceShared},
			{Name: "dockerconfig", Workspace: workspaceDockerConfig},
		},
		TaskSpec: &tektonv1.EmbeddedTask{
			TaskSpec: tektonv1.TaskSpec{
				Params: []tektonv1.ParamSpec{
					{Name: "IMAGE", Type: tektonv1.ParamTypeString},
				},
				Workspaces: []tektonv1.WorkspaceDeclaration{
					{Name: "source"},
					{Name: "dockerconfig"},
				},
				Results: []tektonv1.TaskResult{
					// IMAGE_URL + IMAGE_DIGEST is the pair Tekton Chains reads to learn
					// what a run produced. The push is where the image is published,
					// so it is the task that reports it.
					{Name: "IMAGE_URL", Description: "Image reference that was pushed"},
					{Name: "IMAGE_DIGEST", Description: "Digest of the image manifest as pushed to the registry"},
				},
				Steps: []tektonv1.Step{
					{
						Name:  "push",
						Image: "quay.io/skopeo/stable:latest",
						Env: []corev1.EnvVar{
							{Name: "DOCKER_CONFIG", Value: "/workspace/dockerconfig"},
						},
						Script: `#!/bin/sh
set -e
# The manifest is rewritten on push, so its digest differs from the build
# archive's. --digestfile records the digest the registry will serve; that is
# the one that must be signed, attested and deployed.
skopeo copy \
  --dest-authfile /workspace/dockerconfig/config.json \
  --digestfile /tmp/pushed-digest \
  docker-archive:/workspace/source/image.tar \
  docker://$(params.IMAGE)
printf '%s' "$(cat /tmp/pushed-digest)" > $(results.IMAGE_DIGEST.path)
printf '%s' "$(params.IMAGE)" > $(results.IMAGE_URL.path)
echo "Pushed $(params.IMAGE)@$(cat /tmp/pushed-digest)"
`,
					},
				},
			},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
		},
	}
}

func trivyTask(runAfter string) tektonv1.PipelineTask {
	// Uses docker.io/nkanyezisolutions/trivy-db:latest — a custom image with
	// the vulnerability DB pre-baked at build time. No DB downloads at runtime.
	// --skip-db-update and --skip-java-db-update are set in the task itself.
	// Rebuild the image periodically: see dependencies/tekton/task/trivy-db/Dockerfile
	return tektonv1.PipelineTask{
		Name:     stepTrivy,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "trivy-scanner"},
		Timeout:  &metav1.Duration{Duration: 15 * time.Minute},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "manifest-dir", Workspace: workspaceShared},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE_PATH", Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: "$(params.image-ref)",
			}},
			// Scan the archive the build step wrote to the shared workspace, so
			// the image is checked before the push step publishes it.
			{Name: "IMAGE_TAR", Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageArchive,
			}},
			{Name: "SEVERITY", Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: "HIGH,CRITICAL",
			}},
		},
	}
}

func signTask(
	sc *supplyv1alpha1.SupplyChain,
	imageRef, runAfter string,
	sigCtx *signing.RunSigningContext,
) tektonv1.PipelineTask {
	endpoints := signing.EndpointsFor(sc)

	task := signImageTask(imageRef, runAfter, endpoints)
	if sigCtx == nil {
		return task
	}
	// The proofs were collected before the run started; without them there is
	// nothing to attest, and the signature alone still stands.
	predicate, err := sigCtx.AuthorizationPredicateJSON()
	if err != nil {
		return task
	}
	withAuthorizationAttestation(&task, predicate)
	return task
}

// withAuthorizationAttestation extends the sign task so the three
// authorization proofs are attested to the image by the same keyless identity
// that signed it. SupplyChainPolicy requires this attestation at admission.
func withAuthorizationAttestation(task *tektonv1.PipelineTask, predicate string) {
	spec := &task.TaskSpec.TaskSpec
	sign := spec.Steps[len(spec.Steps)-1]

	spec.Params = append(spec.Params, tektonv1.ParamSpec{Name: "AUTHORIZATION_PREDICATE", Type: tektonv1.ParamTypeString})
	task.Params = append(task.Params, tektonv1.Param{
		Name:  "AUTHORIZATION_PREDICATE",
		Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: predicate},
	})

	spec.Steps = append(spec.Steps,
		tektonv1.Step{
			// The cosign image has no shell, so the predicate file is written
			// by a step that does. It goes through the environment so the JSON
			// is never interpreted by the shell.
			Name:  "write-authorization-predicate",
			Image: "busybox:1.36",
			Env:   []corev1.EnvVar{{Name: "PREDICATE", Value: "$(params.AUTHORIZATION_PREDICATE)"}},
			Script: `#!/bin/sh
set -e
printf '%s' "${PREDICATE}" > ` + authorizationPredicatePath + `
`,
		},
		tektonv1.Step{
			Name:         "attest-authorization",
			Image:        sign.Image,
			VolumeMounts: sign.VolumeMounts,
			Env:          sign.Env,
			Args: []string{
				"attest",
				"--predicate=" + authorizationPredicatePath,
				"--type=" + signing.AuthorizationPredicateType,
				"--fulcio-url=$(params.FULCIO_URL)",
				"--rekor-url=$(params.REKOR_URL)",
				"--oidc-issuer=" + signing.KubernetesOIDCIssuer,
				"--yes",
				"$(params.IMAGE)@$(params.DIGEST)",
			},
		},
	)
}

func signImageTask(imageRef, runAfter string, endpoints signing.Endpoints) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepSign,
		RunAfter: after(runAfter),
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "dockerconfig", Workspace: workspaceDockerConfig},
		},
		TaskSpec: &tektonv1.EmbeddedTask{
			TaskSpec: tektonv1.TaskSpec{
				Params: []tektonv1.ParamSpec{
					{Name: "IMAGE", Type: tektonv1.ParamTypeString},
					{Name: "DIGEST", Type: tektonv1.ParamTypeString},
					{Name: "FULCIO_URL", Type: tektonv1.ParamTypeString},
					{Name: "REKOR_URL", Type: tektonv1.ParamTypeString},
				},
				Workspaces: []tektonv1.WorkspaceDeclaration{
					{Name: "dockerconfig"},
				},
				Volumes: []corev1.Volume{
					{
						Name: "oidc-info",
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								Sources: []corev1.VolumeProjection{
									{
										ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
											Path:              "oidc-token",
											ExpirationSeconds: int64Ptr(600),
											Audience:          "sigstore",
										},
									},
								},
							},
						},
					},
					{
						// blanketops-sigstore-roots holds the three trust anchors
						// for the in-cluster sigstore stack:
						//   fulcio-root.pem — Fulcio CA root
						//   rekor.pub       — Rekor transparency log public key
						//   ctfe.pub        — CT log public key
						// Created by the installer before any pipeline runs.
						Name: "sigstore-roots",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: signing.RootsConfigMap,
								},
							},
						},
					},
				},
				Steps: []tektonv1.Step{
					{
						// Sign by digest — ensures Rekor indexes by the content hash.
						// Cosign WARNING about tags goes away, and the retrieve API
						// can find the entry by sha256 digest.
						// IMAGE@DIGEST format: docker.io/org/repo:tag@sha256:abc...
						Name:  "sign",
						Image: cosignImage,
						VolumeMounts: []corev1.VolumeMount{
							{Name: "oidc-info", MountPath: "/var/run/sigstore/cosign"},
							{Name: "sigstore-roots", MountPath: sigstoreRootsMountPath},
						},
						Env: []corev1.EnvVar{
							{Name: "COSIGN_EXPERIMENTAL", Value: "1"},
							{Name: "SIGSTORE_ID_TOKEN_FILE", Value: "/var/run/sigstore/cosign/oidc-token"},
							{Name: "DOCKER_CONFIG", Value: "/workspace/dockerconfig"},
							{Name: "SIGSTORE_ROOT_FILE", Value: sigstoreRootsMountPath + "/" + signing.RootsFulcioKey},
							{Name: "SIGSTORE_REKOR_PUBLIC_KEY", Value: sigstoreRootsMountPath + "/" + signing.RootsRekorKey},
							{Name: "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", Value: sigstoreRootsMountPath + "/" + signing.RootsCTLogKey},
						},
						Args: []string{
							"sign",
							"--fulcio-url=$(params.FULCIO_URL)",
							"--rekor-url=$(params.REKOR_URL)",
							"--oidc-issuer=" + signing.KubernetesOIDCIssuer,
							"--yes",
							"$(params.IMAGE)@$(params.DIGEST)",
						},
					},
				},
			},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "DIGEST", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepPushImage + ".results.IMAGE_DIGEST)"}},
			{Name: "FULCIO_URL", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: endpoints.FulcioURL}},
			{Name: "REKOR_URL", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: endpoints.RekorURL}},
		},
	}
}
func attestTask(imageRef, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepAttest,
		RunAfter: after(runAfter),
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "dockerconfig", Workspace: workspaceDockerConfig},
		},
		TaskSpec: &tektonv1.EmbeddedTask{
			TaskSpec: tektonv1.TaskSpec{
				Params: []tektonv1.ParamSpec{
					{Name: "IMAGE", Type: tektonv1.ParamTypeString},
				},
				Workspaces: []tektonv1.WorkspaceDeclaration{
					{Name: "dockerconfig"},
				},
				Results: []tektonv1.TaskResult{
					{Name: "IMAGE_URL", Description: "Image URL for Tekton Chains"},
					{Name: "IMAGE_DIGEST", Description: "Image digest for Tekton Chains attestation"},
				},
				Steps: []tektonv1.Step{
					{
						Name:  "attest",
						Image: "quay.io/skopeo/stable:latest",
						Script: `#!/bin/sh
set -e
digest=$(skopeo inspect \
  --authfile /workspace/dockerconfig/config.json \
  docker://$(params.IMAGE) \
  | grep '"Digest"' \
  | awk -F'"' '{print $4}')
if [ -z "$digest" ]; then
  echo "ERROR: could not resolve digest for $(params.IMAGE)"
  exit 1
fi
printf '%s' "$(params.IMAGE)" > $(results.IMAGE_URL.path)
printf '%s' "${digest}" > $(results.IMAGE_DIGEST.path)
echo "IMAGE_URL=$(params.IMAGE)"
echo "IMAGE_DIGEST=${digest}"
`,
					},
				},
			},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
		},
	}
}

// verifyTask is the last step of a build: it verifies the pushed image against
// what a SupplyChainPolicy requires at admission. The signature must come from
// the SupplyChain's ServiceAccount, with a Fulcio certificate chaining to the
// trust anchors, a CT log proof and a Rekor entry; and the authorization
// attestation must be signed the same way and show all three proofs allowed.
func verifyTask(sc *supplyv1alpha1.SupplyChain, imageRef, runAfter string) tektonv1.PipelineTask {
	endpoints := signing.EndpointsFor(sc)
	serviceAccount := sc.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	identity := signing.ServiceAccountIdentity(sc.Namespace, serviceAccount)
	policy := signing.AuthorizationPolicyCUE(authz.Principal(sc.Namespace, serviceAccount))

	trust := []corev1.EnvVar{
		{Name: "DOCKER_CONFIG", Value: "/workspace/dockerconfig"},
		{Name: "SIGSTORE_ROOT_FILE", Value: sigstoreRootsMountPath + "/" + signing.RootsFulcioKey},
		{Name: "SIGSTORE_REKOR_PUBLIC_KEY", Value: sigstoreRootsMountPath + "/" + signing.RootsRekorKey},
		{Name: "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", Value: sigstoreRootsMountPath + "/" + signing.RootsCTLogKey},
	}
	roots := []corev1.VolumeMount{{Name: "sigstore-roots", MountPath: sigstoreRootsMountPath}}
	signer := []string{
		"--certificate-identity=$(params.IDENTITY)",
		"--certificate-oidc-issuer=" + signing.KubernetesOIDCIssuer,
		"--rekor-url=$(params.REKOR_URL)",
	}
	const image = "$(params.IMAGE)@$(params.DIGEST)"
	str := func(name, value string) tektonv1.Param {
		return tektonv1.Param{Name: name, Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: value}}
	}

	return tektonv1.PipelineTask{
		Name:     stepVerify,
		RunAfter: after(runAfter),
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "dockerconfig", Workspace: workspaceDockerConfig},
		},
		TaskSpec: &tektonv1.EmbeddedTask{
			TaskSpec: tektonv1.TaskSpec{
				Params: []tektonv1.ParamSpec{
					{Name: "IMAGE", Type: tektonv1.ParamTypeString},
					{Name: "DIGEST", Type: tektonv1.ParamTypeString},
					{Name: "REKOR_URL", Type: tektonv1.ParamTypeString},
					{Name: "IDENTITY", Type: tektonv1.ParamTypeString},
					{Name: "AUTHORIZATION_POLICY", Type: tektonv1.ParamTypeString},
				},
				Workspaces: []tektonv1.WorkspaceDeclaration{{Name: "dockerconfig"}},
				Results: []tektonv1.TaskResult{
					{Name: "POLICY_VERIFICATION", Description: "PASS when the signature and the authorization attestation verified"},
					{Name: "VERIFIED_SIGNER", Description: "Certificate identity both were verified against"},
				},
				Volumes: []corev1.Volume{{
					Name: "sigstore-roots",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: signing.RootsConfigMap},
						},
					},
				}},
				Steps: []tektonv1.Step{
					{
						// The cosign image has no shell; see withAuthorizationAttestation.
						Name:  "write-authorization-policy",
						Image: "busybox:1.36",
						Env:   []corev1.EnvVar{{Name: "POLICY", Value: "$(params.AUTHORIZATION_POLICY)"}},
						Script: `#!/bin/sh
set -e
printf '%s' "${POLICY}" > ` + authorizationPolicyPath + `
`,
					},
					{
						Name:         "verify-signature",
						Image:        cosignImage,
						VolumeMounts: roots,
						Env:          trust,
						Args:         append(append([]string{"verify"}, signer...), image),
					},
					{
						Name:         "verify-authorization",
						Image:        cosignImage,
						VolumeMounts: roots,
						Env:          trust,
						Args: append(append([]string{
							"verify-attestation",
							"--type=" + signing.AuthorizationPredicateType,
							"--policy=" + authorizationPolicyPath,
						}, signer...), image),
					},
					{
						// Only reached when both verifications passed: a failing
						// step stops the task, so the results stay unset.
						Name:  "report",
						Image: "busybox:1.36",
						Env: []corev1.EnvVar{
							{Name: "IMAGE", Value: image},
							{Name: "IDENTITY", Value: "$(params.IDENTITY)"},
							{Name: "REKOR_URL", Value: "$(params.REKOR_URL)"},
						},
						Script: `#!/bin/sh
set -e
printf '%s' "PASS" > $(results.POLICY_VERIFICATION.path)
printf '%s' "${IDENTITY}" > $(results.VERIFIED_SIGNER.path)
echo "Supply chain policy verification"
echo "  Image:          ${IMAGE}"
echo "  Signer:         ${IDENTITY}"
echo "  Issuer:         ` + signing.KubernetesOIDCIssuer + `"
echo "  Signature:      verified (Fulcio certificate, CT log proof, Rekor entry)"
echo "  Authorization:  verified (scope, intent, output allowed)"
echo "  Rekor:          ${REKOR_URL}"
echo "  Result:         PASS"
`,
					},
				},
			},
		},
		Params: tektonv1.Params{
			str("IMAGE", imageRef),
			str("DIGEST", "$(tasks."+stepPushImage+".results.IMAGE_DIGEST)"),
			str("REKOR_URL", endpoints.RekorURL),
			str("IDENTITY", identity),
			str("AUTHORIZATION_POLICY", policy),
		},
	}
}

func after(task string) []string {
	if task == "" {
		return nil
	}
	return []string{task}
}

func int64Ptr(i int64) *int64 {
	return &i
}
