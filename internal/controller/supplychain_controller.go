/*
Copyright 2026.
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
package controller

import (
	"context"
	"fmt"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

const (
	supplyChainFinalizer = "supplychain.blanketops.dev/finalizer"
)

// SupplyChainReconciler reconciles a SupplyChain object
type SupplyChainReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychains,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychains/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychains/finalizers,verbs=update
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks,verbs=get;list;watch;create;update;patch;delete

func (r *SupplyChainReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues(
		"controller", "supplychain",
		"namespace", req.Namespace,
		"name", req.Name,
	)

	var sc supplyv1alpha1.SupplyChain
	if err := r.Get(ctx, req.NamespacedName, &sc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !sc.DeletionTimestamp.IsZero() {
		logger.Info("handling deletion")
		return r.handleDeletion(ctx, &sc)
	}

	// Ensure finalizer
	if !controllerutil.ContainsFinalizer(&sc, supplyChainFinalizer) {
		logger.Info("adding finalizer")
		controllerutil.AddFinalizer(&sc, supplyChainFinalizer)
		if err := r.Update(ctx, &sc); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Enforce 1:1 repo constraint
	if err := r.enforceRepoUniqueness(ctx, &sc); err != nil {
		logger.Error(err, "repo uniqueness violation", "repository", sc.Spec.Repository)
		return r.setPhase(ctx, &sc, "Error", err)
	}

	// Reconcile custom Tasks
	if err := r.reconcileTasks(ctx, &sc); err != nil {
		logger.Error(err, "failed to reconcile tasks")
		return r.setPhase(ctx, &sc, "Degraded", err)
	}

	// Mark Ready — all Tasks exist, ImageBuilds can now proceed
	sc.Status.Phase = "Ready"
	if err := r.Status().Update(ctx, &sc); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("SupplyChain ready", "repository", sc.Spec.Repository)
	return ctrl.Result{}, nil
}

// reconcileTasks ensures all custom Tekton Tasks exist and are up-to-date in the namespace.
// Hub Tasks (buildpacks, git-clone, trivy-scanner) are cluster prerequisites.
func (r *SupplyChainReconciler) reconcileTasks(ctx context.Context, sc *supplyv1alpha1.SupplyChain) error {
	logger := log.FromContext(ctx)

	for _, desired := range customTasks(sc.Namespace) {
		task := desired
		result, err := controllerutil.CreateOrUpdate(ctx, r.Client, &task, func() error {
			task.Spec = desired.Spec
			return nil
		})
		if err != nil {
			return fmt.Errorf("reconciling Task %q: %w", task.Name, err)
		}
		logger.Info("task reconciled", "task", task.Name, "result", result)
	}

	return nil
}

// customTasks returns the embedded Task definitions managed by the SupplyChain controller.
// These are distinct from Hub Tasks which are cluster-level prerequisites.
func customTasks(namespace string) []tektonv1.Task {
	return []tektonv1.Task{
		sonarQubeTask(namespace),
		cosignSignTask(namespace),
		tektonChainsAttestTask(namespace),
		grafeasPublishTask(namespace),
	}
}

func sonarQubeTask(namespace string) tektonv1.Task {
	return tektonv1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sonarqube-scanner",
			Namespace: namespace,
		},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{Name: "SONAR_HOST_URL", Type: tektonv1.ParamTypeString, Description: "SonarQube server URL"},
				{Name: "SONAR_PROJECT_KEY", Type: tektonv1.ParamTypeString, Description: "SonarQube project key"},
				{Name: "SONAR_TOKEN_SECRET", Type: tektonv1.ParamTypeString, Description: "Secret name containing the SonarQube token",
					Default: &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "sonarqube-token"}},
			},
			Steps: []tektonv1.Step{
				{
					Name:  "sonar-scan",
					Image: "sonarsource/sonar-scanner-cli:latest",
					Env: []corev1.EnvVar{
						{
							Name: "SONAR_TOKEN",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "$(params.SONAR_TOKEN_SECRET)"},
									Key:                  "token",
								},
							},
						},
					},
					Args: []string{
						"-Dsonar.host.url=$(params.SONAR_HOST_URL)",
						"-Dsonar.projectKey=$(params.SONAR_PROJECT_KEY)",
						"-Dsonar.login=$(SONAR_TOKEN)",
					},
				},
			},
		},
	}
}

func cosignSignTask(namespace string) tektonv1.Task {
	return tektonv1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cosign-sign",
			Namespace: namespace,
		},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{Name: "IMAGE", Type: tektonv1.ParamTypeString, Description: "Image reference to sign"},
				{Name: "FULCIO_URL", Type: tektonv1.ParamTypeString, Description: "Fulcio CA URL",
					Default: &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "https://fulcio.sigstore.dev"}},
				{Name: "REKOR_URL", Type: tektonv1.ParamTypeString, Description: "Rekor transparency log URL",
					Default: &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "https://rekor.sigstore.dev"}},
			},
			Steps: []tektonv1.Step{
				{
					Name:  "sign",
					Image: "gcr.io/projectsigstore/cosign:v2.2.3",
					Env: []corev1.EnvVar{
						{Name: "COSIGN_EXPERIMENTAL", Value: "1"},
					},
					Args: []string{
						"sign",
						"--fulcio-url=$(params.FULCIO_URL)",
						"--rekor-url=$(params.REKOR_URL)",
						"--yes",
						"$(params.IMAGE)",
					},
				},
			},
		},
	}
}

func tektonChainsAttestTask(namespace string) tektonv1.Task {
	return tektonv1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tekton-chains-attest",
			Namespace: namespace,
		},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{Name: "IMAGE", Type: tektonv1.ParamTypeString, Description: "Image reference to attest"},
			},
			Results: []tektonv1.TaskResult{
				{Name: "IMAGE_URL", Type: tektonv1.ResultsTypeString, Description: "Image URL for Tekton Chains"},
				{Name: "IMAGE_DIGEST", Type: tektonv1.ResultsTypeString, Description: "Image digest for Tekton Chains attestation"},
			},
			Steps: []tektonv1.Step{
				{
					Name:  "attest",
					Image: "gcr.io/go-containerregistry/crane:latest",
					Script: `#!/bin/sh
set -e
digest=$(crane digest $(params.IMAGE))
echo -n "$(params.IMAGE)" | tee $(results.IMAGE_URL.path)
echo -n "${digest}" | tee $(results.IMAGE_DIGEST.path)
echo "IMAGE_URL=$(params.IMAGE)"
echo "IMAGE_DIGEST=${digest}"`,
				},
			},
		},
	}
}

func grafeasPublishTask(namespace string) tektonv1.Task {
	return tektonv1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grafeas-publish",
			Namespace: namespace,
		},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{Name: "IMAGE", Type: tektonv1.ParamTypeString, Description: "Fully qualified image reference"},
				{Name: "GRAFEAS_HOST", Type: tektonv1.ParamTypeString, Description: "Grafeas gRPC host:port"},
				{Name: "PROJECT_ID", Type: tektonv1.ParamTypeString, Description: "Grafeas project ID"},
			},
			Steps: []tektonv1.Step{
				{
					Name:  "publish",
					Image: "alpine:latest",
					Script: `#!/bin/sh
set -e

echo "Installing tools..."
apk add --no-cache git 2>/dev/null
wget -qO /tmp/grpcurl.tar.gz \
  https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz
tar -xzf /tmp/grpcurl.tar.gz -C /usr/local/bin grpcurl

echo "Fetching grafeas protos..."
git clone --quiet --depth=1 --filter=blob:none \
  https://github.com/grafeas/grafeas.git /tmp/grafeas
git clone --quiet --depth=1 --filter=blob:none \
  https://github.com/googleapis/googleapis.git /tmp/googleapis

HOST="$(params.GRAFEAS_HOST)"
PROJECT="$(params.PROJECT_ID)"
IMAGE="$(params.IMAGE)"
GRPC="-plaintext -import-path /tmp/grafeas -import-path /tmp/googleapis -proto proto/v1beta1/grafeas.proto"

echo "Creating note (idempotent)..."
grpcurl $GRPC \
  -d "{
    \"parent\": \"projects/${PROJECT}\",
    \"noteId\": \"build\",
    \"note\": {
      \"shortDescription\": \"BlanketOps build note\",
      \"kind\": \"BUILD\",
      \"build\": {\"builderVersion\": \"blanketops-v1\"}
    }
  }" \
  ${HOST} grafeas.v1beta1.GrafeasV1Beta1/CreateNote \
  || echo "Note may already exist, continuing..."

echo "Publishing occurrence..."
grpcurl $GRPC \
  -d "{
    \"parent\": \"projects/${PROJECT}\",
    \"occurrence\": {
      \"resource\": {\"uri\": \"${IMAGE}\"},
      \"noteName\": \"projects/${PROJECT}/notes/build\",
      \"kind\": \"BUILD\",
      \"build\": {
        \"provenance\": {
          \"id\": \"$(context.taskRun.name)\",
          \"projectId\": \"${PROJECT}\",
          \"builtArtifacts\": [{
            \"id\": \"${IMAGE}\",
            \"names\": [\"${IMAGE}\"]
          }]
        }
      }
    }
  }" \
  ${HOST} grafeas.v1beta1.GrafeasV1Beta1/CreateOccurrence

echo "Metadata published successfully"`,
				},
			},
		},
	}
}

func (r *SupplyChainReconciler) enforceRepoUniqueness(ctx context.Context, sc *supplyv1alpha1.SupplyChain) error {
	var list supplyv1alpha1.SupplyChainList
	if err := r.List(ctx, &list, client.InNamespace(sc.Namespace)); err != nil {
		return err
	}
	for _, existing := range list.Items {
		if existing.Name == sc.Name {
			continue
		}
		if existing.Spec.Repository == sc.Spec.Repository {
			return fmt.Errorf("repository %q is already claimed by SupplyChain %q — one SupplyChain per repository is law",
				sc.Spec.Repository, existing.Name)
		}
	}
	return nil
}

func (r *SupplyChainReconciler) handleDeletion(ctx context.Context, sc *supplyv1alpha1.SupplyChain) (ctrl.Result, error) {
	controllerutil.RemoveFinalizer(sc, supplyChainFinalizer)
	if err := r.Update(ctx, sc); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *SupplyChainReconciler) setPhase(ctx context.Context, sc *supplyv1alpha1.SupplyChain, phase string, cause error) (ctrl.Result, error) {
	sc.Status.Phase = phase
	_ = r.Status().Update(ctx, sc)
	if cause != nil {
		return ctrl.Result{}, cause
	}
	return ctrl.Result{}, nil
}

func (r *SupplyChainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&supplyv1alpha1.SupplyChain{}).
		Owns(&supplyv1alpha1.ImageBuild{}).
		Owns(&tektonv1.Task{}).
		Complete(r)
}
