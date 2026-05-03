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
package controller

import (
	"context"
	"fmt"
	"time"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	supplychain "github.com/ntlaletsi70/secure-software-supply-chain/internal/controller/mediators/supplychain"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
	pipeline "github.com/ntlaletsi70/secure-software-supply-chain/pkg/tekton/pipeline"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/tekton/pruner"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/tekton/results"
)

type ImageBuildReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Clientset kubernetes.Interface
	Mediator  *supplychain.Mediator
	Recorder  *results.Recorder
	Pruner    *pruner.Pruner
	Signature *signing.SignatureReconciler
}

// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuildresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuildresults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagesignatures,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagesignatures/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tekton.dev,resources=pipelineruns;pipelines;taskruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=external-secrets.io,resources=externalsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts;secrets;events;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
func (r *ImageBuildReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues(
		"controller", "imagebuild",
		"namespace", req.Namespace,
		"name", req.Name,
	)

	var ib supplychainv1alpha1.ImageBuild
	if err := r.Get(ctx, req.NamespacedName, &ib); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Terminal state guard.
	if ib.Status.Phase == "Succeeded" || ib.Status.Phase == "Failed" {
		logger.Info("ImageBuild terminal, skipping", "phase", ib.Status.Phase)
		return ctrl.Result{}, nil
	}

	// ── 1. Resolve SupplyChain ────────────────────────────────────────────
	var sc supplychainv1alpha1.SupplyChain
	if err := r.Get(ctx, types.NamespacedName{
		Name:      ib.Spec.SupplyChainRef.Name,
		Namespace: ib.Namespace,
	}, &sc); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("SupplyChain not found yet, waiting",
				"supplyChain", ib.Spec.SupplyChainRef.Name,
			)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		logger.Error(err, "failed to fetch SupplyChain")
		return ctrl.Result{}, err
	}

	if sc.Status.Phase != "Ready" {
		logger.Info("SupplyChain not ready yet, waiting", "phase", sc.Status.Phase)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// ── 2. Reconcile PipelineRun ──────────────────────────────────────────
	pr, result, err := r.reconcilePipelineRun(ctx, &ib, &sc)
	if err != nil {
		logger.Error(err, "failed to reconcile PipelineRun")
		return r.setFailed(ctx, &ib, err)
	}
	if result != nil {
		return *result, nil
	}

	// ── 3. Sync status ────────────────────────────────────────────────────
	if pr != nil {
		r.syncStatus(ctx, &ib, pr)
	}

	logger.Info("ImageBuild reconciled",
		"phase", ib.Status.Phase,
		"pipelineRun", ib.Status.PipelineRunRef,
	)

	// ── 4. Terminal actions ───────────────────────────────────────────────
	// All best-effort — errors logged, reconcile does not fail.
	if pr != nil && pr.IsDone() {
		// 4a. Record ImageBuildResult
		if err := r.Recorder.Record(ctx, &ib, pr); err != nil {
			logger.Error(err, "failed to record ImageBuildResult")
		}

		// 4b. Reconcile ImageSignature
		// sigCtx fields are stored on Status before the PipelineRun is created.
		// Read them back here — the cert and principal survive in Status.
		if ib.Status.Phase == "Succeeded" {
			_, imageDigest := results.ExtractImageResults(pr)
			if err := r.Signature.MarkSigned(
				ctx, &ib, imageDigest,
				[]byte(ib.Status.SigningCertPEM),
			); err != nil {
				logger.Error(err, "failed to mark ImageSignature signed")
			}
		} else {
			if err := r.Signature.MarkFailed(ctx, &ib); err != nil {
				logger.Error(err, "failed to mark ImageSignature failed")
			}
		}

		// 4c. Prune old PipelineRuns
		if err := r.Pruner.PruneForImageBuild(ctx, &ib); err != nil {
			logger.Error(err, "failed to prune PipelineRuns")
		}

		return ctrl.Result{}, nil
	}

	if ib.Status.Phase == "Running" || ib.Status.Phase == "Pending" {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

// pipelineRunName generates a deterministic PipelineRun name from the
// ImageBuild name that always fits within Kubernetes' 63-char limit.
func pipelineRunName(ib *supplychainv1alpha1.ImageBuild) string {
	// ImageBuild name format: <supplychain>-<branch>-<sha>
	// PipelineRun format:     pr-<supplychain>-<short-sha>
	// e.g. pr-for-kaniko-app-408e8fce
	sha := ib.Spec.GitRef.Revision
	if len(sha) > 8 {
		sha = sha[:8]
	}
	name := fmt.Sprintf("pr-%s-%s", ib.Spec.SupplyChainRef.Name, sha)
	// Kubernetes name limit is 63 chars
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

func (r *ImageBuildReconciler) reconcilePipelineRun(
	ctx context.Context,
	ib *supplychainv1alpha1.ImageBuild,
	sc *supplychainv1alpha1.SupplyChain,
) (*tektonv1.PipelineRun, *ctrl.Result, error) {
	logger := log.FromContext(ctx)

	prName := pipelineRunName(ib)

	// Idempotency — return existing PipelineRun if already created.
	var existing tektonv1.PipelineRun
	err := r.Get(ctx, types.NamespacedName{Name: prName, Namespace: ib.Namespace}, &existing)
	if err == nil {
		return &existing, nil, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, nil, fmt.Errorf("fetching PipelineRun: %w", err)
	}

	// ── Gate 1: prerequisites (secrets, SA) ──────────────────────────────
	ready, err := r.Mediator.EnsurePrerequisites(ctx, sc, ib)
	if err != nil {
		return nil, nil, err
	}
	if !ready {
		logger.Info("waiting for prerequisites (secrets)")
		return nil, &ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// ── Gate 2: signing context (SAR → Token → Fulcio) ───────────────────
	sigCtx, err := r.Mediator.EstablishSigningContext(ctx, sc, ib)
	if err != nil {
		return nil, nil, fmt.Errorf("signing context: %w", err)
	}
	logger.Info("signing context ready",
		"principal", sigCtx.ScopeProof.Principal,
		"certExpiry", sigCtx.Cert.ExpiresAt,
	)

	// ── Build image reference ─────────────────────────────────────────────
	imageTag := ib.Spec.ImageTag
	if imageTag == "" {
		imageTag = ib.Spec.GitRef.Revision
	}
	imageRef := fmt.Sprintf("%s/%s:%s",
		sc.Spec.Image.Registry,
		sc.Spec.Image.Name,
		imageTag,
	)

	// ── Ensure ImageSignature (Pending) before PipelineRun ───────────────
	// Created early so the signing identity is recorded before execution.
	// The cert and principal are stored on Status so the terminal block
	// can read them back without needing the sigCtx in scope.
	if err := r.Signature.EnsureSignature(ctx, ib, sc, sigCtx, imageRef); err != nil {
		logger.Error(err, "failed to ensure ImageSignature")
		// non-fatal — continue
	}

	// ── Build and create PipelineRun ─────────────────────────────────────
	pr := pipeline.BuildPipelineRun(prName, ib.Namespace, sc, ib, imageRef, sigCtx)
	if pr.Labels == nil {
		pr.Labels = map[string]string{}
	}
	pr.Labels["blanketops.dev/image-build"] = ib.Name

	if err := controllerutil.SetControllerReference(ib, pr, r.Scheme); err != nil {
		return nil, nil, err
	}

	if err := r.Create(ctx, pr); err != nil {
		return nil, nil, fmt.Errorf("creating PipelineRun: %w", err)
	}

	logger.Info("PipelineRun created",
		"pipelineRun", prName,
		"image", imageRef,
		"imageBuild", ib.Name,
	)

	// ── Store signing identity on Status for terminal block ───────────────
	// sigCtx is scoped to this method. Store what the terminal block needs.
	now := metav1.Now()
	ib.Status.Phase = "Pending"
	ib.Status.PipelineRunRef = prName
	ib.Status.ImageRef = imageRef
	ib.Status.StartTime = &now
	ib.Status.SignedBy = sigCtx.ScopeProof.Principal
	ib.Status.SigningCertPEM = string(sigCtx.Cert.CertPEM)
	_ = r.Status().Update(ctx, ib)

	return pr, nil, nil
}

func (r *ImageBuildReconciler) syncStatus(
	ctx context.Context,
	ib *supplychainv1alpha1.ImageBuild,
	pr *tektonv1.PipelineRun,
) {
	if pr == nil {
		return
	}

	logger := log.FromContext(ctx)

	if pr.IsDone() {
		now := metav1.Now()
		ib.Status.CompletionTime = &now

		if pr.Status.GetCondition("Succeeded").IsTrue() {
			ib.Status.Phase = "Succeeded"
			logger.Info("ImageBuild succeeded", "image", ib.Status.ImageRef)
		} else {
			ib.Status.Phase = "Failed"
			logger.Info("ImageBuild failed")
		}
	} else if pr.HasStarted() {
		ib.Status.Phase = "Running"
	}

	var steps []supplychainv1alpha1.StepStatus
	for _, child := range pr.Status.PipelineRunStatusFields.ChildReferences {
		steps = append(steps, supplychainv1alpha1.StepStatus{
			Name:  child.Name,
			Phase: string(child.DisplayName),
		})
	}
	if len(steps) > 0 {
		ib.Status.Steps = steps
	}

	_ = r.Status().Update(ctx, ib)
}

func (r *ImageBuildReconciler) setFailed(
	ctx context.Context,
	ib *supplychainv1alpha1.ImageBuild,
	err error,
) (ctrl.Result, error) {
	ib.Status.Phase = "Failed"
	_ = r.Status().Update(ctx, ib)
	return ctrl.Result{}, err
}

func (r *ImageBuildReconciler) SetupWithManager(mgr ctrl.Manager) error {
	log := ctrl.Log.WithName("controllers").WithName("ImageBuild")
	recorder := mgr.GetEventRecorderFor("imagebuild-controller")

	config := mgr.GetConfig()
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	r.Clientset = clientset

	r.Mediator = supplychain.New(
		mgr.GetClient(),
		clientset,
		mgr.GetScheme(),
		log.WithName("mediator"),
		recorder,
	)

	r.Recorder = results.New(
		mgr.GetClient(),
		log.WithName("recorder"),
	)

	r.Pruner = pruner.New(
		mgr.GetClient(),
		log.WithName("pruner"),
	)

	r.Signature = signing.NewSignatureReconciler(
		mgr.GetClient(),
		log.WithName("signature"),
	)

	return ctrl.NewControllerManagedBy(mgr).
		For(&supplychainv1alpha1.ImageBuild{}).
		Owns(&tektonv1.PipelineRun{}).
		Complete(r)
}
