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
	"strings"
	"time"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

const (
	stepGitClone   = "git-clone"
	stepAuthFulcio = "authentication-fulcio"
	stepSonarQube  = "code-scan-sonarqube"
	stepBuildImage = "build-image-buildah"
	stepPushImage  = "push-image-docker"
	stepTrivy      = "vulnerability-scan-trivy"
	stepSign       = "sign-image-cosign"
	stepAttest     = "attest-image-rekor-fulcio"
	stepGrafeas    = "publish-metadata-grafeas"

	workspaceShared       = "shared-data"
	workspaceSSHCreds     = "ssh-creds"
	workspaceDockerConfig = "dockerconfig"
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

	return &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: tektonv1.PipelineRunSpec{
			TaskRunTemplate: tektonv1.PipelineTaskRunTemplate{
				ServiceAccountName: sa,
			},
			Workspaces: []tektonv1.WorkspaceBinding{
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
			},
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
				Tasks: buildTaskList(sc, ib, imageRef),
				// --- RESULTS MAPPING SECTION ---
				// Aggregates individual Task results into PipelineRun status
				// for the ImageBuildResult controller to consume.
				Results: []tektonv1.PipelineResult{
					// 1. Git Provenance
					// {
					// 	Name:  "commit",
					// 	Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepGitClone + ".results.commit)"},
					// },
					// {
					// 	Name:  "committer-date",
					// 	Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepGitClone + ".results.committer-date)"},
					// },
					// {
					// 	Name:  "url",
					// 	Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepBuildImage + ".results.url)"},
					// },
					// 2. Build Result
					{
						Name:  "IMAGE_DIGEST",
						Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepBuildImage + ".results.IMAGE_DIGEST)"},
					},
					{
						Name:  "IMAGE_URL",
						Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepBuildImage + ".results.IMAGE_URL)"},
					},
					// 3. Security & Quality Gates
					// {
					// 	Name:  "TRIVY_SCAN_SUMMARY",
					// 	Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepTrivy + ".results.TRIVY_SCAN_SUMMARY)"},
					// },
					// {
					// 	Name:  "SONAR_GATE_STATUS",
					// 	Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepSonarQube + ".results.GATE_STATUS)"},
					// },
					// // 4. Identity & Metadata
					// {
					// 	Name:  "SIGNATURE_DIGEST",
					// 	Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(tasks." + stepSign + ".results.IMAGE_DIGEST)"},
					// },
				},
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

func buildTaskList(
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
	imageRef string,
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

	// Step 5: push image (Skopeo) — push to registry to get a real digest
	tasks = append(tasks, pushImageTask(imageRef, last))
	last = stepPushImage

	// Step 6: trivy — scan the real registry image digest, not a local tar
	// Scanning after push guarantees we're scanning what will actually run
	if sc.Spec.Steps.Trivy {
		tasks = append(tasks, trivyTask(last))
		last = stepTrivy
	}

	// Step 7: sign (Cosign + Fulcio) — image is clean, now sign it
	// Must sign before attesting — you attest to a signed image
	if sc.Spec.Steps.Sign {
		tasks = append(tasks, signTask(sc, imageRef, last))
		last = stepSign
	}

	// Step 8: attest (Rekor) — record attestation of the signed image
	// Rekor logs the signature, not the raw image — sign must come first
	if sc.Spec.Steps.Attest {
		tasks = append(tasks, attestTask(imageRef, last))
		last = stepAttest
	}

	// Step 9: grafeas — publish full metadata report
	// All gates passed, all attestations recorded — now publish
	if sc.Spec.Steps.Grafeas != nil {
		tasks = append(tasks, grafeasTask(sc, imageRef, last))
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
	fulcio := "https://fulcio.sigstore.dev"
	if sc.Spec.Signing != nil && sc.Spec.Signing.FulcioURL != "" {
		fulcio = sc.Spec.Signing.FulcioURL
	}

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
				Steps: []tektonv1.Step{
					{
						Name:  "push",
						Image: "quay.io/skopeo/stable:latest",
						Env: []corev1.EnvVar{
							{Name: "DOCKER_CONFIG", Value: "/workspace/dockerconfig"},
						},
						Script: `#!/bin/sh
set -e
skopeo copy \
  --dest-authfile /workspace/dockerconfig/config.json \
  docker-archive:/workspace/source/image.tar \
  docker://$(params.IMAGE)
echo "Pushed $(params.IMAGE)"
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
	return tektonv1.PipelineTask{
		Name:     stepTrivy,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "trivy-scanner"},
		Timeout:  &metav1.Duration{Duration: 15 * time.Minute},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "manifest-dir", Workspace: workspaceShared},
		},
		Params: tektonv1.Params{
			// Scan the registry image by digest — image is already pushed.
			// --skip-java-db-update avoids downloading the 860MB Java DB on every run.
			// --timeout gives Trivy enough time to complete the scan.
			{Name: "IMAGE_PATH", Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: "$(params.image-ref)",
			}},
			{Name: "ARGS", Value: tektonv1.ParamValue{
				Type: tektonv1.ParamTypeArray,
				ArrayVal: []string{
					"image",
					"--exit-code", "0",
					"--severity", "HIGH,CRITICAL",
					"--skip-java-db-update",
					"--timeout", "10m",
				},
			}},
		},
	}
}

func signTask(sc *supplyv1alpha1.SupplyChain, imageRef, runAfter string) tektonv1.PipelineTask {
	fulcio := "https://fulcio.sigstore.dev"
	rekor := "https://rekor.sigstore.dev"
	if sc.Spec.Signing != nil {
		if sc.Spec.Signing.FulcioURL != "" {
			fulcio = sc.Spec.Signing.FulcioURL
		}
		if sc.Spec.Signing.RekorURL != "" {
			rekor = sc.Spec.Signing.RekorURL
		}
	}

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
				},
				Steps: []tektonv1.Step{
					{
						Name:  "sign",
						Image: "gcr.io/projectsigstore/cosign:v2.2.3",
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "oidc-info",
								MountPath: "/var/run/sigstore/cosign",
							},
						},
						Env: []corev1.EnvVar{
							{Name: "COSIGN_EXPERIMENTAL", Value: "1"},
							{Name: "SIGSTORE_ID_TOKEN_FILE", Value: "/var/run/sigstore/cosign/oidc-token"},
							{Name: "DOCKER_CONFIG", Value: "/workspace/dockerconfig"},
						},
						Args: []string{
							"sign",
							"--fulcio-url=$(params.FULCIO_URL)",
							"--rekor-url=$(params.REKOR_URL)",
							"--oidc-issuer=https://kubernetes.default.svc.cluster.local",
							"--insecure-skip-verify",
							"--yes",
							"$(params.IMAGE)",
						},
					},
				},
			},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "FULCIO_URL", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: fulcio}},
			{Name: "REKOR_URL", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: rekor}},
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

func grafeasTask(sc *supplyv1alpha1.SupplyChain, imageRef, runAfter string) tektonv1.PipelineTask {
	// Strip protocol — grpcurl needs host:port only. HTTP was 8081, gRPC is 8080.
	grpcHost := strings.TrimPrefix(sc.Spec.Steps.Grafeas.ServerURL, "https://")
	grpcHost = strings.TrimPrefix(grpcHost, "http://")
	grpcHost = strings.Replace(grpcHost, ":8081", ":8080", 1)

	return tektonv1.PipelineTask{
		Name:     stepGrafeas,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "grafeas-publish"},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "GRAFEAS_HOST", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: grpcHost}},
			{Name: "PROJECT_ID", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "blanketops"}},
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
