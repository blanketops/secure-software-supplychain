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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	webhookmediator "github.com/ntlaletsi70/secure-software-supply-chain/internal/controller/mediators/githubwebhook"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/github"
)

const (
	githubWebhookFinalizer = "supplychain.blanketops.dev/githubwebhook-finalizer"
)

// GitHubWebhookReconciler reconciles a GitHubWebhook object.
type GitHubWebhookReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Mediator *webhookmediator.Mediator
}

// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=githubwebhooks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=githubwebhooks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=githubwebhooks/finalizers,verbs=update
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychains,verbs=get;list;watch
// +kubebuilder:rbac:groups=external-secrets.io,resources=externalsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *GitHubWebhookReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues(
		"controller", "githubwebhook",
		"namespace", req.Namespace,
		"name", req.Name,
	)

	var ghw supplychainv1alpha1.GitHubWebhook
	if err := r.Get(ctx, req.NamespacedName, &ghw); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// ── Deletion ──────────────────────────────────────────────────────────
	if !ghw.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &ghw)
	}

	// ── Finalizer ─────────────────────────────────────────────────────────
	if !controllerutil.ContainsFinalizer(&ghw, githubWebhookFinalizer) {
		logger.Info("adding finalizer")
		controllerutil.AddFinalizer(&ghw, githubWebhookFinalizer)
		if err := r.Update(ctx, &ghw); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// ── Gate 1: wait for SupplyChain to be Ready ──────────────────────────
	var sc supplychainv1alpha1.SupplyChain
	if err := r.Get(ctx, types.NamespacedName{
		Name:      ghw.Spec.SupplyChainRef.Name,
		Namespace: ghw.Namespace,
	}, &sc); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("SupplyChain not found yet, waiting",
				"supplyChain", ghw.Spec.SupplyChainRef.Name,
			)
			return r.setPhase(ctx, &ghw, "Pending", "SupplyChainNotFound",
				fmt.Sprintf("SupplyChain %q not found", ghw.Spec.SupplyChainRef.Name),
				&ctrl.Result{RequeueAfter: 5 * time.Second})
		}
		return ctrl.Result{}, err
	}

	if sc.Status.Phase != "Ready" {
		logger.Info("SupplyChain not ready yet, waiting", "phase", sc.Status.Phase)
		return r.setPhase(ctx, &ghw, "Pending", "SupplyChainNotReady",
			fmt.Sprintf("SupplyChain %q is not Ready (phase: %s)", sc.Name, sc.Status.Phase),
			&ctrl.Result{RequeueAfter: 5 * time.Second})
	}

	// ── Gate 2: mediator — ExternalSecrets + convergence ─────────────────
	ready, err := r.Mediator.EnsurePrerequisites(ctx, &ghw)
	if err != nil {
		logger.Error(err, "prerequisites failed")
		return r.setPhase(ctx, &ghw, "Failed", "PrerequisitesFailed", err.Error(), nil)
	}
	if !ready {
		logger.Info("waiting for secrets to be materialised by ESO")
		return r.setPhase(ctx, &ghw, "Pending", "WaitingForSecrets",
			"waiting for GitHub token secret to be materialised by ESO",
			&ctrl.Result{RequeueAfter: 5 * time.Second})
	}

	// ── Gate 3: resolve secrets ───────────────────────────────────────────
	token, err := r.Mediator.ResolveToken(ctx, &ghw)
	if err != nil {
		logger.Error(err, "failed to resolve GitHub token")
		return r.setPhase(ctx, &ghw, "Failed", "TokenResolutionFailed", err.Error(), nil)
	}

	webhookSecret, err := r.Mediator.ResolveWebhookSecret(ctx, &ghw)
	if err != nil {
		logger.Error(err, "failed to resolve webhook secret")
		return r.setPhase(ctx, &ghw, "Failed", "WebhookSecretResolutionFailed", err.Error(), nil)
	}

	// ── Build GitHub client ───────────────────────────────────────────────
	ghClient := github.NewClient(token)

	// ── Idempotency: check if webhook already registered ─────────────────
	if ghw.Status.WebhookID != 0 {
		exists, err := ghClient.WebhookExists(ctx, ghw.Spec.Repository, ghw.Status.WebhookID)
		if err != nil {
			logger.Error(err, "failed to check webhook existence")
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}

		if exists {
			// Up to date — nothing to do.
			if ghw.Status.HookURL == ghw.Spec.HookURL &&
				ghw.Status.ObservedGeneration == ghw.Generation {
				logger.Info("webhook up to date, nothing to do",
					"webhookID", ghw.Status.WebhookID,
					"repository", ghw.Spec.Repository,
				)
				return ctrl.Result{}, nil
			}

			// Spec changed — update.
			logger.Info("spec changed, updating webhook", "webhookID", ghw.Status.WebhookID)
			if err := ghClient.UpdateWebhook(ctx,
				ghw.Spec.Repository,
				ghw.Status.WebhookID,
				ghw.Spec.HookURL,
				ghw.Spec.Events,
				webhookSecret,
				ghw.Spec.InsecureSSL,
				ghw.Spec.ContentType,
			); err != nil {
				logger.Error(err, "failed to update webhook")
				return r.setPhase(ctx, &ghw, "Failed", "WebhookUpdateFailed", err.Error(), nil)
			}

			logger.Info("webhook updated", "webhookID", ghw.Status.WebhookID)
			return r.markReady(ctx, &ghw, ghw.Status.WebhookID)
		}

		// Stored ID no longer exists on GitHub — fall through to re-register.
		logger.Info("stored webhook no longer exists on GitHub, re-registering")
	}

	// ── Register webhook ──────────────────────────────────────────────────
	logger.Info("registering webhook with GitHub",
		"repository", ghw.Spec.Repository,
		"hookURL", ghw.Spec.HookURL,
	)

	if err := r.setPhaseOnly(ctx, &ghw, "Registering", "Registering",
		"Registering webhook with GitHub"); err != nil {
		return ctrl.Result{}, err
	}

	webhookID, err := ghClient.CreateWebhook(ctx,
		ghw.Spec.Repository,
		ghw.Spec.HookURL,
		ghw.Spec.Events,
		webhookSecret,
		ghw.Spec.InsecureSSL,
		ghw.Spec.ContentType,
	)
	if err != nil {
		logger.Error(err, "failed to register webhook with GitHub")
		return r.setPhase(ctx, &ghw, "Failed", "WebhookRegistrationFailed", err.Error(), nil)
	}

	logger.Info("webhook registered",
		"webhookID", webhookID,
		"repository", ghw.Spec.Repository,
		"hookURL", ghw.Spec.HookURL,
	)

	return r.markReady(ctx, &ghw, webhookID)
}

// handleDeletion removes the webhook from GitHub then removes the finalizer.
func (r *GitHubWebhookReconciler) handleDeletion(
	ctx context.Context,
	ghw *supplychainv1alpha1.GitHubWebhook,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(ghw, githubWebhookFinalizer) {
		if ghw.Status.WebhookID != 0 {
			token, err := r.Mediator.ResolveToken(ctx, ghw)
			if err != nil {
				logger.Info("token unavailable during deletion, skipping GitHub API call")
			} else {
				ghClient := github.NewClient(token)
				if err := ghClient.DeleteWebhook(ctx, ghw.Spec.Repository, ghw.Status.WebhookID); err != nil {
					logger.Error(err, "failed to delete webhook from GitHub — removing finalizer anyway",
						"webhookID", ghw.Status.WebhookID,
					)
				} else {
					logger.Info("webhook deleted from GitHub",
						"webhookID", ghw.Status.WebhookID,
						"repository", ghw.Spec.Repository,
					)
				}
			}
		}

		controllerutil.RemoveFinalizer(ghw, githubWebhookFinalizer)
		if err := r.Update(ctx, ghw); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// markReady updates status to Ready with the registered webhook ID.
func (r *GitHubWebhookReconciler) markReady(
	ctx context.Context,
	ghw *supplychainv1alpha1.GitHubWebhook,
	webhookID int64,
) (ctrl.Result, error) {
	now := metav1.Now()
	ghw.Status.Phase = "Ready"
	ghw.Status.WebhookID = webhookID
	ghw.Status.HookURL = ghw.Spec.HookURL
	ghw.Status.Repository = ghw.Spec.Repository
	ghw.Status.LastRegisteredAt = &now
	ghw.Status.ObservedGeneration = ghw.Generation

	ghwSetCondition(ghw, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "WebhookRegistered",
		Message:            fmt.Sprintf("Webhook %d registered for %s", webhookID, ghw.Spec.Repository),
		ObservedGeneration: ghw.Generation,
	})

	if err := r.Status().Update(ctx, ghw); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// setPhase updates status phase and condition, optionally requeuing.
func (r *GitHubWebhookReconciler) setPhase(
	ctx context.Context,
	ghw *supplychainv1alpha1.GitHubWebhook,
	phase, reason, message string,
	result *ctrl.Result,
) (ctrl.Result, error) {
	if err := r.setPhaseOnly(ctx, ghw, phase, reason, message); err != nil {
		return ctrl.Result{}, err
	}
	if result != nil {
		return *result, nil
	}
	return ctrl.Result{}, nil
}

// setPhaseOnly updates phase and condition without returning a result.
func (r *GitHubWebhookReconciler) setPhaseOnly(
	ctx context.Context,
	ghw *supplychainv1alpha1.GitHubWebhook,
	phase, reason, message string,
) error {
	ghw.Status.Phase = phase

	condStatus := metav1.ConditionFalse
	if phase == "Ready" {
		condStatus = metav1.ConditionTrue
	} else if phase == "Pending" || phase == "Registering" {
		condStatus = metav1.ConditionUnknown
	}

	ghwSetCondition(ghw, metav1.Condition{
		Type:               "Ready",
		Status:             condStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ghw.Generation,
	})

	return r.Status().Update(ctx, ghw)
}

// ghwSetCondition upserts a condition on the GitHubWebhook status.
// Named distinctly to avoid collision with setCondition in supplychain_controller.go.
func ghwSetCondition(ghw *supplychainv1alpha1.GitHubWebhook, condition metav1.Condition) {
	condition.LastTransitionTime = metav1.Now()
	for i, c := range ghw.Status.Conditions {
		if c.Type == condition.Type {
			if c.Status == condition.Status {
				condition.LastTransitionTime = c.LastTransitionTime
			}
			ghw.Status.Conditions[i] = condition
			return
		}
	}
	ghw.Status.Conditions = append(ghw.Status.Conditions, condition)
}

// SetupWithManager sets up the controller with the Manager.
func (r *GitHubWebhookReconciler) SetupWithManager(mgr ctrl.Manager) error {
	recorder := mgr.GetEventRecorderFor("githubwebhook-controller")

	r.Mediator = webhookmediator.New(
		mgr.GetClient(),
		mgr.GetScheme(),
		ctrl.Log.WithName("controllers").WithName("GitHubWebhook").WithName("mediator"),
		recorder,
	)

	return ctrl.NewControllerManagedBy(mgr).
		For(&supplychainv1alpha1.GitHubWebhook{}).
		Named("githubwebhook").
		Complete(r)
}
