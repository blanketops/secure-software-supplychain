package tekton

import (
	"fmt"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplyv1alpha1 "github.com/ntlaletsi70/blanketops-environments-supply-chain/api/v1alpha1"
)

const (
	stepGitClone  = "git-clone"
	stepKaniko    = "kaniko"
	stepSonarQube = "sonarqube"
	stepTrivy     = "trivy"
	stepSign      = "sign"
	stepAttest    = "attest"
	stepGrafeas   = "grafeas"

	workspaceSource   = "source"
	workspaceSSHCreds = "ssh-creds"
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
					Name:     workspaceSource,
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
				{
					Name: workspaceSSHCreds,
					Secret: &corev1.SecretVolumeSource{
						SecretName: sc.Spec.Image.CloneSecretRef,
					},
				},
			},

			PipelineSpec: &tektonv1.PipelineSpec{
				Workspaces: []tektonv1.PipelineWorkspaceDeclaration{
					{Name: workspaceSource},
					{Name: workspaceSSHCreds},
				},

				Params: []tektonv1.ParamSpec{
					{Name: "image-ref", Type: tektonv1.ParamTypeString},
					{Name: "git-url", Type: tektonv1.ParamTypeString},
					{Name: "git-revision", Type: tektonv1.ParamTypeString},
				},

				Tasks: []tektonv1.PipelineTask{
					gitCloneTask(),
					kanikoTask(imageRef, stepGitClone),
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

func gitCloneTask() tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:    stepGitClone,
		TaskRef: &tektonv1.TaskRef{Name: "git-clone"},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "output", Workspace: workspaceSource},
			{Name: "ssh-directory", Workspace: workspaceSSHCreds}, // 🔥 REQUIRED
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

// ------------------------------------------------------------
// OTHER TASKS (UNCHANGED)
// ------------------------------------------------------------

func after(task string) []string {
	if task == "" {
		return nil
	}
	return []string{task}
}

// (rest unchanged)

// ------------------------------------------------------------
// TASK DEFINITIONS
// ------------------------------------------------------------

func kanikoTask(imageRef, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepKaniko,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "kaniko"},
		Workspaces: []tektonv1.WorkspacePipelineTaskBinding{
			{Name: "source", Workspace: workspaceSource},
		},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "DOCKERFILE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "$(workspaces.source.path)/Dockerfile"}},
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
			{Name: "SONAR_PROJECT_KEY", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sc.Spec.Repository}},
			{Name: "SONAR_TOKEN_SECRET", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sc.Spec.Steps.SonarQube.TokenSecretRef}},
		},
	}
}

func trivyTask(imageRef, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepTrivy,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "trivy-scanner"},
		Params: tektonv1.Params{
			{Name: "IMAGE_PATH", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "ARGS", Value: tektonv1.ParamValue{
				Type:     tektonv1.ParamTypeArray,
				ArrayVal: []string{"--exit-code", "1", "--severity", "HIGH,CRITICAL"},
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
		TaskRef:  &tektonv1.TaskRef{Name: "cosign-sign"},
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
		TaskRef:  &tektonv1.TaskRef{Name: "tekton-chains-attest"},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
		},
	}
}

func grafeasTask(sc *supplyv1alpha1.SupplyChain, imageRef, runAfter string) tektonv1.PipelineTask {
	return tektonv1.PipelineTask{
		Name:     stepGrafeas,
		RunAfter: after(runAfter),
		TaskRef:  &tektonv1.TaskRef{Name: "grafeas-publish"},
		Params: tektonv1.Params{
			{Name: "IMAGE", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef}},
			{Name: "GRAFEAS_URL", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: sc.Spec.Steps.Grafeas.ServerURL}},
			{Name: "PROJECT_ID", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: fmt.Sprintf("blanketops/%s", sc.Spec.Repository)}},
		},
	}
}
