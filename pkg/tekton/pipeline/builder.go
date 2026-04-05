package pipeline

import (
	"strings"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplyv1alpha1 "github.com/ntlaletsi70/blanketops-environments-supply-chain/api/v1alpha1"
)

const (
	stepGitClone   = "git-clone"
	stepKaniko     = "kaniko"
	stepSonarQube  = "sonarqube"
	stepTrivy      = "trivy"
	stepAuthFulcio = "auth-fulcio"
	stepSign       = "sign"
	stepAttest     = "attest"
	stepGrafeas    = "grafeas"

	workspaceShared       = "shared-data"
	workspaceSSHCreds     = "ssh-creds"
	workspaceDockerConfig = "dockerconfig"
)

func BuildPipelineRun(
	name, namespace string,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
	imageRef string,
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
									corev1.ResourceStorage: resource.MustParse("1Gi"),
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

	// Step 0: git clone
	tasks = append(tasks, gitCloneTask())
	last := stepGitClone

	// Step 1: build
	tasks = append(tasks, kanikoTask(imageRef, last))
	last = stepKaniko

	// Step 2: sonar
	if sc.Spec.Steps.SonarQube != nil {
		tasks = append(tasks, sonarQubeTask(sc, last))
		last = stepSonarQube
	}

	// Step 3: trivy
	if sc.Spec.Steps.Trivy {
		tasks = append(tasks, trivyTask(imageRef, last))
		last = stepTrivy
	}

	// Step 4: auth-fulcio + sign
	if sc.Spec.Steps.Sign {
		tasks = append(tasks, authFulcioTask(sc, last))
		tasks = append(tasks, signTask(sc, imageRef, stepAuthFulcio))
		last = stepSign
	}

	// Step 5: attest
	if sc.Spec.Steps.Attest {
		tasks = append(tasks, attestTask(imageRef, last))
		last = stepAttest
	}

	// Step 6: grafeas
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

func kanikoTask(imageRef, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepKaniko,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "kaniko"},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "source", Workspace: workspaceShared},
			{Name: "dockerconfig", Workspace: workspaceDockerConfig},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "DOCKERFILE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "Dockerfile"}},
			{Name: "CONTEXT", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "."}},
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

func trivyTask(imageRef, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepTrivy,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "trivy-scanner"},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "manifest-dir", Workspace: workspaceShared},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE_PATH", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "ARGS", Value: tektonv1.ParamValue{
				Type:     tektonv1.ParamTypeArray,
				ArrayVal: []string{"--exit-code", "1", "--severity", "HIGH,CRITICAL"},
			}},
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
						Image: "alpine/crane:latest",
						Env: []corev1.EnvVar{
							{Name: "IMAGE", Value: imageRef},
							{Name: "DOCKER_CONFIG", Value: "/workspace/dockerconfig"},
						},
						Script: `#!/bin/sh
set -e
digest=$(crane digest ${IMAGE})
printf '%s' "${IMAGE}" > $(results.IMAGE_URL.path)
printf '%s' "${digest}" > $(results.IMAGE_DIGEST.path)
echo "IMAGE_URL=${IMAGE}"
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
	// ✅ Keep Grafeas project flat (NO slashes)
	projectID := "blanketops"

	grafeasURL := sc.Spec.Steps.Grafeas.ServerURL

	// Normalize to host:port for grpcurl
	grpcHost := strings.TrimPrefix(grafeasURL, "http://")
	grpcHost = strings.TrimPrefix(grpcHost, "https://")

	return tektonv1.PipelineTask{
		Name:     stepGrafeas,
		RunAfter: after(runAfter),
		TaskSpec: &tektonv1.EmbeddedTask{
			TaskSpec: tektonv1.TaskSpec{
				Params: []tektonv1.ParamSpec{
					{Name: "IMAGE", Type: tektonv1.ParamTypeString},
					{Name: "GRAFEAS_URL", Type: tektonv1.ParamTypeString},
					{Name: "PROJECT_ID", Type: tektonv1.ParamTypeString},
				},
				Steps: []tektonv1.Step{
					{
						Name: "publish",
						// ✅ Use a prebuilt image (YOU should build this once)
						Image: "ghcr.io/your-org/grafeas-client:latest",
						Env: []corev1.EnvVar{
							{Name: "GRAFEAS_HOST", Value: grpcHost},
							{Name: "PROJECT_ID", Value: projectID},
							{Name: "IMAGE_REF", Value: imageRef},
						},
						Script: `#!/bin/sh
set -ex

echo "Using Grafeas host: ${GRAFEAS_HOST}"
echo "Project: ${PROJECT_ID}"
echo "Image: ${IMAGE_REF}"

PROTO_PATH="/opt/grafeas/proto"

echo "🔎 Checking Grafeas connectivity..."
grpcurl -plaintext ${GRAFEAS_HOST} list || {
  echo "❌ Cannot reach Grafeas gRPC endpoint"
  exit 1
}

echo "📝 Creating Grafeas note (idempotent)..."
grpcurl -plaintext \
  -import-path ${PROTO_PATH} \
  -proto grafeas/v1beta1/grafeas.proto \
  -d "{
    \"name\": \"projects/${PROJECT_ID}/notes/build\",
    \"short_description\": \"BlanketOps build note\",
    \"kind\": \"NOTE_KIND_BUILD\",
    \"build\": {
      \"builder_version\": \"blanketops-v1\"
    }
  }" \
  ${GRAFEAS_HOST} \
  grafeas.v1beta1.GrafeasV1Beta1/CreateNote \
  || echo "⚠️ Note may already exist"

echo "📦 Publishing occurrence..."
grpcurl -plaintext \
  -import-path ${PROTO_PATH} \
  -proto grafeas/v1beta1/grafeas.proto \
  -d "{
    \"resource_uri\": \"${IMAGE_REF}\",
    \"note_name\": \"projects/${PROJECT_ID}/notes/build\",
    \"kind\": \"NOTE_KIND_BUILD\",
    \"build\": {
      \"provenance\": {
        \"id\": \"blanketops-run\",
        \"project_id\": \"${PROJECT_ID}\",
        \"built_artifacts\": [{
          \"id\": \"${IMAGE_REF}\",
          \"names\": [\"${IMAGE_REF}\"]
        }]
      }
    }
  }" \
  ${GRAFEAS_HOST} \
  grafeas.v1beta1.GrafeasV1Beta1/CreateOccurrence \
  || {
    echo "❌ Failed to create occurrence"
    exit 1
  }

echo "✅ Metadata successfully published to Grafeas"
`,
					},
				},
			},
		},
		Params: tektonv1.Params{
			{
				Name: "IMAGE",
				Value: tektonv1.ParamValue{
					Type:      tektonv1.ParamTypeString,
					StringVal: imageRef,
				},
			},
			{
				Name: "GRAFEAS_URL",
				Value: tektonv1.ParamValue{
					Type:      tektonv1.ParamTypeString,
					StringVal: grafeasURL,
				},
			},
			{
				Name: "PROJECT_ID",
				Value: tektonv1.ParamValue{
					Type:      tektonv1.ParamTypeString,
					StringVal: projectID,
				},
			},
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
