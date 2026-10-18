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
	"strings"
	"time"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	triggersv1beta1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	supplychain "github.com/blanketops/secure-software-supplychain/internal/controller/mediators/supplychain"
	"github.com/blanketops/secure-software-supplychain/pkg/evidence"
	"github.com/blanketops/secure-software-supplychain/pkg/signing"
	pipeline "github.com/blanketops/secure-software-supplychain/pkg/tekton/pipeline"
	"github.com/blanketops/secure-software-supplychain/pkg/tekton/results"
)

const (
	// evidenceRetry is how often a finished build is revisited while Tekton
	// Chains has not signed its run yet; evidenceWait is for how long.
	evidenceRetry = 20 * time.Second
	evidenceWait  = 10 * time.Minute

	// Phases of an ImageBuild, written to and compared against Status.Phase.
	phasePending   = "Pending"
	phaseRunning   = "Running"
	phaseSucceeded = "Succeeded"
	phaseFailed    = "Failed"
)

type ImageBuildReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Mediator  *supplychain.Mediator
	Recorder  *results.Recorder
	Signature *signing.SignatureReconciler
	// APIReader reads past the informer cache. It confirms a build's
	// PipelineRun is really gone, which the cache cannot: a run the reconciler
	// has only just created may not be in it yet. Defaults to the manager's.
	APIReader client.Reader
}

// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuildresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuildresults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagesignatures,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuildresults/finalizers,verbs=update
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagesignatures/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagesignatures/finalizers,verbs=update
// +kubebuilder:rbac:groups=tekton.dev,resources=pipelineruns;pipelines;taskruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=external-secrets.io,resources=externalsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts;secrets;events;configmaps,verbs=get;list;watch;create;update;patch;delete
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

	// Terminal state guard. A build that succeeded is only revisited for the
	// evidence Tekton Chains adds after the run has finished.
	if ib.Status.Phase == phaseSucceeded {
		return r.completeEvidence(ctx, &ib)
	}
	if ib.Status.Phase == phaseFailed {
		logger.Info("ImageBuild terminal, skipping", "phase", ib.Status.Phase)
		return ctrl.Result{}, nil
	}

	// A build whose PipelineRun is gone has finished: Tekton Pruner deletes
	// runs some minutes after they end. Settle it from what was recorded;
	// creating the run again would build and sign the commit a second time.
	if settled, err := r.settleIfRunDeleted(ctx, &ib); settled || err != nil {
		return ctrl.Result{}, err
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

		// 4b. Reconcile ImageSignature from what was just recorded.
		if ib.Status.Phase == phaseSucceeded {
			if err := r.recordSignature(ctx, &ib); err != nil {
				logger.Error(err, "Failed to record ImageSignature")
			}
		} else {
			if err := r.Signature.MarkFailed(ctx, &ib); err != nil {
				logger.Error(err, "failed to mark ImageSignature failed")
			}
		}

		// Tekton Chains signs the run after it has finished, and adds that
		// provenance to the image. Come back for it, so the recorded
		// evidence is whole; give up on a run Chains never signs. Tekton
		// Pruner deletes the run only after this wait (its retention is
		// longer than evidenceWait).
		if ib.Status.Phase == phaseSucceeded && !evidence.ChainsDone(pr) && pr.Status.CompletionTime != nil &&
			time.Since(pr.Status.CompletionTime.Time) < evidenceWait {
			return ctrl.Result{RequeueAfter: evidenceRetry}, nil
		}

		// 4c. The record is final: store the evidence in immudb, then publish
		// the record to Tekton. A build whose evidence is not stored is
		// reconciled again, and not published.
		if err := r.Recorder.StoreEvidence(ctx, &ib); err != nil {
			logger.Error(err, "Failed to store the build's evidence in immudb")
			return ctrl.Result{}, err
		}
		if err := r.publishResult(ctx, &ib, pr.Name); err != nil {
			logger.Error(err, "Failed to publish ImageBuildResult to Tekton")
		}
		return ctrl.Result{}, nil
	}

	if ib.Status.Phase == phaseRunning || ib.Status.Phase == phasePending {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

// pipelineRunName generates a deterministic PipelineRun name from the
// ImageBuild name that always fits within Kubernetes' 63-char limit.
func pipelineRunName(ib *supplychainv1alpha1.ImageBuild) string {
	// ImageBuild name format: <supplychain>-<branch>-<fullsha>
	// Strip the supplychain prefix to get <branch>-<fullsha>
	ibName := ib.Name
	sc := ib.Spec.SupplyChainRef.Name
	remainder := strings.TrimPrefix(ibName, sc+"-")

	// remainder is now "<branch>-<fullsha>"
	// split on last "-" to separate branch from sha
	lastDash := strings.LastIndex(remainder, "-")
	branch := remainder
	sha := ""
	if lastDash != -1 {
		branch = remainder[:lastDash]
		fullSHA := remainder[lastDash+1:]
		if len(fullSHA) > 8 {
			sha = fullSHA[:8]
		} else {
			sha = fullSHA
		}
	}

	// run-<supplychain>-<branch>-<short-sha>
	// e.g. run-your-app-master-5728a219
	//
	// A build made by hand need not be named that way: "your-app-demo" has no
	// sha, and one not named after its SupplyChain has neither part in the
	// expected place. Empty parts are left out, and nothing is left dangling
	// by the cut to 63 characters, so the name is always a valid one.
	name := "run-" + sc
	for _, part := range []string{branch, sha} {
		if part != "" {
			name += "-" + part
		}
	}
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimRight(name, "-.")
}
func (r *ImageBuildReconciler) reconcilePipelineRun(ctx context.Context, ib *supplychainv1alpha1.ImageBuild, sc *supplychainv1alpha1.SupplyChain) (*tektonv1.PipelineRun, *ctrl.Result, error) {
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
	// Read how this cluster's workloads identify themselves to Fulcio before
	// anything is signed: the pipeline, Chains and the admission policy all
	// take it from the same configuration.
	identity, err := signing.LoadIdentity(ctx, r.Client)
	if err != nil {
		return nil, nil, fmt.Errorf("signing configuration: %w", err)
	}

	sigCtx, err := r.Mediator.EstablishSigningContext(ctx, sc, ib)
	if err != nil {
		return nil, nil, fmt.Errorf("signing context: %w", err)
	}
	sigCtx.Identity = identity
	logger.Info("signing context ready",
		"identityProvider", identity.Provider,
		"principal", sigCtx.ScopeProof.Principal,
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
	// Created early so who the build runs as is on record before execution.
	// The signature itself is recorded when the build is over, from the
	// registry and the transparency log.
	if err := r.Signature.EnsureSignature(ctx, ib, sc, sigCtx, imageRef); err != nil {
		logger.Error(err, "failed to ensure ImageSignature")
		// non-fatal — continue
	}

	// ── Build and create PipelineRun ─────────────────────────────────────
	pr := pipeline.BuildPipelineRun(prName, ib.Namespace, sc, ib, imageRef, sigCtx)
	if pr.Labels == nil {
		pr.Labels = map[string]string{}
	}
	pr.Labels["blanketops.dev/image-build"] = ib.LabelValue()

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
	ib.Status.Phase = phasePending
	ib.Status.PipelineRunRef = prName
	ib.Status.ImageRef = imageRef
	ib.Status.StartTime = &now
	ib.Status.SignedBy = sigCtx.ScopeProof.Principal
	_ = r.Status().Update(ctx, ib)

	return pr, nil, nil
}

func (r *ImageBuildReconciler) syncStatus(ctx context.Context, ib *supplychainv1alpha1.ImageBuild, pr *tektonv1.PipelineRun) {
	if pr == nil {
		return
	}

	logger := log.FromContext(ctx)

	if pr.IsDone() {
		now := metav1.Now()
		ib.Status.CompletionTime = &now

		if pr.Status.GetCondition("Succeeded").IsTrue() {
			ib.Status.Phase = phaseSucceeded
			logger.Info("ImageBuild succeeded", "image", ib.Status.ImageRef)
		} else {
			ib.Status.Phase = phaseFailed
			logger.Info("ImageBuild failed")
		}
	} else if pr.HasStarted() {
		ib.Status.Phase = phaseRunning
	}

	if ib.Status.Phase == phaseSucceeded {
		_, ib.Status.ImageDigest = results.ExtractImageResults(pr)
	}

	if steps := r.stepStatuses(ctx, pr); len(steps) > 0 {
		ib.Status.Steps = steps
	}

	if err := r.Status().Update(ctx, ib); err != nil {
		logger.Error(err, "Failed to update ImageBuild status")
	}
}

// stepStatuses reports each pipeline task of pr and how far it got. The
// PipelineRun only lists its TaskRuns by name, so their conditions are read
// from the TaskRuns themselves.
func (r *ImageBuildReconciler) stepStatuses(ctx context.Context, pr *tektonv1.PipelineRun) []supplychainv1alpha1.StepStatus {
	var taskRuns tektonv1.TaskRunList
	if err := r.List(ctx, &taskRuns,
		client.InNamespace(pr.Namespace),
		client.MatchingLabels{"tekton.dev/pipelineRun": pr.Name},
	); err != nil {
		log.FromContext(ctx).Error(err, "Failed to list TaskRuns", "pipelineRun", pr.Name)
		return nil
	}
	phases := make(map[string]string, len(taskRuns.Items))
	for i := range taskRuns.Items {
		phase := phaseRunning
		switch condition := taskRuns.Items[i].Status.GetCondition("Succeeded"); {
		case condition == nil:
			phase = phasePending
		case condition.IsTrue():
			phase = phaseSucceeded
		case condition.IsFalse():
			phase = phaseFailed
		}
		phases[taskRuns.Items[i].Name] = phase
	}

	var steps []supplychainv1alpha1.StepStatus
	for _, child := range pr.Status.ChildReferences {
		phase, found := phases[child.Name]
		if !found {
			phase = phasePending
		}
		steps = append(steps, supplychainv1alpha1.StepStatus{Name: child.PipelineTaskName, Phase: phase})
	}
	return steps
}

// conditionRunDeleted is set on a build whose PipelineRun was deleted after it
// had been created, and says where the build's outcome came from.
const conditionRunDeleted = "PipelineRunDeleted"

// settleIfRunDeleted settles a build whose PipelineRun no longer exists. Only
// a build that already had a run is considered, and the run's absence is
// confirmed past the cache. Its outcome is the one its ImageBuildResult
// recorded when the run finished; without one, for example when the operator
// was down from before the run ended until after it was pruned, the build is
// Failed, as nothing shows it succeeded. The run is never created again.
func (r *ImageBuildReconciler) settleIfRunDeleted(ctx context.Context, ib *supplychainv1alpha1.ImageBuild) (bool, error) {
	if ib.Status.PipelineRunRef == "" {
		return false, nil
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	var pr tektonv1.PipelineRun
	err := reader.Get(ctx, types.NamespacedName{Namespace: ib.Namespace, Name: ib.Status.PipelineRunRef}, &pr)
	if err == nil {
		return false, nil
	}
	if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("checking PipelineRun %s: %w", ib.Status.PipelineRunRef, err)
	}

	phase := phaseFailed
	reason := "NoRecordedOutcome"
	message := fmt.Sprintf("PipelineRun %s was deleted before this build recorded how it ended; "+
		"it is not run again", ib.Status.PipelineRunRef)
	var result supplychainv1alpha1.ImageBuildResult
	switch err := r.Get(ctx, client.ObjectKeyFromObject(ib), &result); {
	case err == nil && (result.Status.Phase == phaseSucceeded || result.Status.Phase == phaseFailed):
		phase = result.Status.Phase
		reason = "OutcomeFromResult"
		message = fmt.Sprintf("PipelineRun %s was deleted after it finished; the outcome is the one "+
			"its ImageBuildResult recorded", ib.Status.PipelineRunRef)
	case err != nil && !apierrors.IsNotFound(err):
		return false, fmt.Errorf("reading ImageBuildResult: %w", err)
	}

	ib.Status.Phase = phase
	meta.SetStatusCondition(&ib.Status.Conditions, metav1.Condition{
		Type:               conditionRunDeleted,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ib.Generation,
	})
	if err := r.Status().Update(ctx, ib); err != nil {
		return false, err
	}
	// As on any failed build, its signature record is failed too, rather than
	// left Pending for a run that will not come back.
	if phase == phaseFailed && r.Signature != nil {
		if err := r.Signature.MarkFailed(ctx, ib); err != nil {
			log.FromContext(ctx).Error(err, "failed to mark ImageSignature failed")
		}
	}
	log.FromContext(ctx).Info("PipelineRun gone; build settled without running it again",
		"pipelineRun", ib.Status.PipelineRunRef, "phase", phase, "reason", reason)
	return true, nil
}

func (r *ImageBuildReconciler) setFailed(ctx context.Context, ib *supplychainv1alpha1.ImageBuild, err error) (ctrl.Result, error) {
	ib.Status.Phase = phaseFailed
	_ = r.Status().Update(ctx, ib)
	return ctrl.Result{}, err
}

// completeEvidence records the evidence of a finished build again until
// Tekton Chains is done with the run. Chains signs a run after it completes
// and stores that provenance with the image, so the first record, taken the
// moment the run finished, cannot have it.
func (r *ImageBuildReconciler) completeEvidence(ctx context.Context, ib *supplychainv1alpha1.ImageBuild) (ctrl.Result, error) {
	var result supplychainv1alpha1.ImageBuildResult
	if err := r.Get(ctx, client.ObjectKeyFromObject(ib), &result); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if result.Status.Evidence != nil && result.Status.Evidence.Complete {
		return ctrl.Result{}, r.finalize(ctx, ib, ib.Status.PipelineRunRef)
	}

	var pr tektonv1.PipelineRun
	key := types.NamespacedName{Namespace: ib.Namespace, Name: ib.Status.PipelineRunRef}
	if err := r.Get(ctx, key, &pr); err != nil {
		// Pruned: there is nothing left to learn about it.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err := r.Recorder.Record(ctx, ib, &pr); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.recordSignature(ctx, ib); err != nil {
		return ctrl.Result{}, err
	}
	if !evidence.ChainsDone(&pr) && pr.Status.CompletionTime != nil &&
		time.Since(pr.Status.CompletionTime.Time) < evidenceWait {
		return ctrl.Result{RequeueAfter: evidenceRetry}, nil
	}
	return ctrl.Result{}, r.finalize(ctx, ib, pr.Name)
}

// finalize stores the final evidence of a build in immudb and then publishes
// its ImageBuildResult to Tekton. An error leaves the build unpublished, to be
// reconciled again.
func (r *ImageBuildReconciler) finalize(ctx context.Context, ib *supplychainv1alpha1.ImageBuild, pipelineRun string) error {
	if err := r.Recorder.StoreEvidence(ctx, ib); err != nil {
		return err
	}
	return r.publishResult(ctx, ib, pipelineRun)
}

// recordSignature completes the ImageSignature of a build from the evidence
// in its ImageBuildResult: the signature as it is stored with the image and
// logged in Rekor, not as the controller assumes it to be.
func (r *ImageBuildReconciler) recordSignature(ctx context.Context, ib *supplychainv1alpha1.ImageBuild) error {
	var result supplychainv1alpha1.ImageBuildResult
	if err := r.Get(ctx, client.ObjectKeyFromObject(ib), &result); err != nil {
		return fmt.Errorf("reading ImageBuildResult: %w", err)
	}
	var missing string
	if result.Status.Evidence == nil {
		missing = "no evidence has been collected for the image yet"
	} else {
		missing = result.Status.Evidence.Message
	}
	return r.Signature.Record(ctx, ib, result.Status.ImageDigest,
		evidence.BuildSignature(result.Status.Evidence), missing)
}

// publishResult creates the CustomRun that shows the ImageBuildResult in
// Tekton. It is created once, when nothing more will be added to the record.
func (r *ImageBuildReconciler) publishResult(ctx context.Context, ib *supplychainv1alpha1.ImageBuild, pipelineRun string) error {
	if pipelineRun == "" {
		return nil
	}
	err := r.Create(ctx, results.NewRun(ib, pipelineRun))
	return client.IgnoreAlreadyExists(err)
}

func (r *ImageBuildReconciler) SetupWithManager(mgr ctrl.Manager) error {
	logger := ctrl.Log.WithName("controllers").WithName("ImageBuild")
	recorder := mgr.GetEventRecorderFor("imagebuild-controller")

	r.Mediator = supplychain.New(
		mgr.GetClient(),
		mgr.GetScheme(),
		logger.WithName("mediator"),
		recorder,
	)

	r.Recorder = results.New(
		mgr.GetClient(),
		logger.WithName("recorder"),
	)

	r.Signature = signing.NewSignatureReconciler(
		mgr.GetClient(),
		logger.WithName("signature"),
	)

	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&supplychainv1alpha1.ImageBuild{}).
		Owns(&tektonv1.PipelineRun{}).
		Owns(&tektonv1.Task{}).
		Owns(&tektonv1.TaskRun{}).
		Owns(&tektonv1.Pipeline{}).
		Owns(&triggersv1beta1.EventListener{}).
		Owns(&triggersv1beta1.TriggerBinding{}).
		Owns(&triggersv1beta1.TriggerTemplate{}).
		Complete(r)
}
