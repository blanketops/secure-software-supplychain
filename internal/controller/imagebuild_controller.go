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

	supplychainv1alpha1 "github.com/ntlaletsi70/blanketops-environments-supply-chain/api/v1alpha1"
	supplychain "github.com/ntlaletsi70/blanketops-environments-supply-chain/internal/controller/mediators/supplychain"
	pipeline "github.com/ntlaletsi70/blanketops-environments-supply-chain/pkg/tekton/pipeline"
)

type ImageBuildReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Clientset kubernetes.Interface
	Mediator  *supplychain.Mediator
}

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

	// Terminal state guard
	if ib.Status.Phase == "Succeeded" || ib.Status.Phase == "Failed" {
		logger.Info("ImageBuild terminal, skipping", "phase", ib.Status.Phase)
		return ctrl.Result{}, nil
	}

	// ---------------------------------------------------------------------
	// 1. Resolve SupplyChain dependency (HARD BLOCKING)
	// ---------------------------------------------------------------------
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
		logger.Info("SupplyChain not ready yet, waiting",
			"phase", sc.Status.Phase,
		)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// ---------------------------------------------------------------------
	// 2. Reconcile PipelineRun (includes mediator gating + signing)
	// ---------------------------------------------------------------------
	pr, result, err := r.reconcilePipelineRun(ctx, &ib, &sc)
	if err != nil {
		logger.Error(err, "failed to reconcile PipelineRun")
		return r.setFailed(ctx, &ib, err)
	}

	// If we are waiting (secrets, signing, etc.)
	if result != nil {
		return *result, nil
	}

	// ---------------------------------------------------------------------
	// 3. Sync status ONLY if PipelineRun exists
	// ---------------------------------------------------------------------
	if pr != nil {
		r.syncStatus(ctx, &ib, pr)
	}

	logger.Info("ImageBuild reconciled",
		"phase", ib.Status.Phase,
		"pipelineRun", ib.Status.PipelineRunRef,
	)

	// Requeue while active
	if ib.Status.Phase == "Running" || ib.Status.Phase == "Pending" {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) reconcilePipelineRun(
	ctx context.Context,
	ib *supplychainv1alpha1.ImageBuild,
	sc *supplychainv1alpha1.SupplyChain,
) (*tektonv1.PipelineRun, *ctrl.Result, error) {
	logger := log.FromContext(ctx)

	prName := ib.Name + "-run"

	// ---------------------------------------------------------------------
	// Existing PipelineRun (idempotency)
	// ---------------------------------------------------------------------
	var existing tektonv1.PipelineRun
	err := r.Get(ctx, types.NamespacedName{Name: prName, Namespace: ib.Namespace}, &existing)
	if err == nil {
		return &existing, nil, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, nil, fmt.Errorf("fetching PipelineRun: %w", err)
	}

	// ---------------------------------------------------------------------
	// Mediator gating — prerequisites (secrets, SA)
	// ---------------------------------------------------------------------
	ready, err := r.Mediator.EnsurePrerequisites(ctx, sc, ib)
	if err != nil {
		return nil, nil, err
	}
	if !ready {
		logger.Info("waiting for prerequisites (secrets)")
		return nil, &ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// ---------------------------------------------------------------------
	// Mediator gating — signing context (SAR → Token → Fulcio)
	// ---------------------------------------------------------------------
	sigCtx, err := r.Mediator.EstablishSigningContext(ctx, sc, ib)
	if err != nil {
		return nil, nil, fmt.Errorf("signing context: %w", err)
	}

	logger.Info("signing context ready",
		"principal", sigCtx.Proof.Principal,
		"certExpiry", sigCtx.Cert.ExpiresAt,
	)

	// ---------------------------------------------------------------------
	// Build PipelineRun
	// ---------------------------------------------------------------------
	imageTag := ib.Spec.ImageTag
	if imageTag == "" {
		imageTag = ib.Spec.GitRef.Revision
	}

	imageRef := fmt.Sprintf("%s/%s:%s",
		sc.Spec.Image.Registry,
		sc.Spec.Image.Name,
		imageTag,
	)

	pr := pipeline.BuildPipelineRun(prName, ib.Namespace, sc, ib, imageRef, sigCtx)

	if err := controllerutil.SetControllerReference(ib, pr, r.Scheme); err != nil {
		return nil, nil, err
	}

	if err := r.Create(ctx, pr); err != nil {
		return nil, nil, fmt.Errorf("creating PipelineRun: %w", err)
	}

	logger.Info("PipelineRun created",
		"pipelineRun", prName,
		"image", imageRef,
	)

	now := metav1.Now()
	ib.Status.Phase = "Pending"
	ib.Status.PipelineRunRef = prName
	ib.Status.ImageRef = imageRef
	ib.Status.StartTime = &now
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

	// Build the kubernetes.Interface clientset from the manager's rest.Config.
	// Needed by the mediator for TokenRequest API calls.
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

	return ctrl.NewControllerManagedBy(mgr).
		For(&supplychainv1alpha1.ImageBuild{}).
		Owns(&tektonv1.PipelineRun{}).
		Complete(r)
}
