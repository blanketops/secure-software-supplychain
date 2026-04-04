package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	supplychainv1alpha1 "github.com/ntlaletsi70/blanketops-environments-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/blanketops-environments-supply-chain/pkg/github/webhook"
	"github.com/ntlaletsi70/blanketops-environments-supply-chain/pkg/github/workflow"
)

const (
	repositorySourceFinalizer = "supplychain.blanketops.dev/repository-source-finalizer"

	conditionTypeReady    = "Ready"
	conditionTypeWebhook  = "WebhookRegistered"
	conditionTypeWorkflow = "WorkflowInjected"

	phaseReady       = "Ready"
	phasePending     = "Pending"
	phaseRegistering = "Registering"
	phaseFailed      = "Failed"
)

// RepositorySourceReconciler reconciles a RepositorySource object
type RepositorySourceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=repositorysources,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=repositorysources/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=repositorysources/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *RepositorySourceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// -------------------------------------------------------------------------
	// Fetch RepositorySource
	// -------------------------------------------------------------------------
	rs := &supplychainv1alpha1.RepositorySource{}
	if err := r.Get(ctx, req.NamespacedName, rs); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// -------------------------------------------------------------------------
	// Finalizer — handle deletion
	// -------------------------------------------------------------------------
	if !rs.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, log, rs)
	}

	if !controllerutil.ContainsFinalizer(rs, repositorySourceFinalizer) {
		controllerutil.AddFinalizer(rs, repositorySourceFinalizer)
		if err := r.Update(ctx, rs); err != nil {
			return ctrl.Result{}, err
		}
	}

	// -------------------------------------------------------------------------
	// Fetch GitHub PAT
	// -------------------------------------------------------------------------
	pat, err := r.fetchSecret(ctx, rs.Namespace, rs.Spec.TokenSecretRef, "token")
	if err != nil {
		return r.failWith(ctx, rs, conditionTypeReady, "TokenSecretNotFound", err)
	}

	// -------------------------------------------------------------------------
	// Fetch HMAC secret
	// -------------------------------------------------------------------------
	hmac, err := r.fetchSecret(ctx, rs.Namespace, rs.Spec.Webhook.HMACSecretRef, "hmac")
	if err != nil {
		return r.failWith(ctx, rs, conditionTypeReady, "HMACSecretNotFound", err)
	}

	// -------------------------------------------------------------------------
	// Parse owner/repo
	// -------------------------------------------------------------------------
	owner, repo, err := parseRepository(rs.Spec.Repository)
	if err != nil {
		return r.failWith(ctx, rs, conditionTypeReady, "InvalidRepository", err)
	}

	// -------------------------------------------------------------------------
	// Set phase → Registering
	// -------------------------------------------------------------------------
	rs.Status.Phase = phaseRegistering
	if err := r.Status().Update(ctx, rs); err != nil {
		return ctrl.Result{}, err
	}

	// -------------------------------------------------------------------------
	// Register webhook
	// -------------------------------------------------------------------------
	webhookClient := webhook.NewClient(ctx, pat)

	if rs.Status.WebhookID == 0 {
		hookID, err := webhookClient.Register(ctx, owner, repo, rs.Spec.ListenerURL, hmac)
		if err != nil {
			return r.failWith(ctx, rs, conditionTypeWebhook, "WebhookRegistrationFailed", err)
		}
		rs.Status.WebhookID = hookID
		log.Info("Webhook registered", "hookID", hookID, "repository", rs.Spec.Repository)
	} else {
		exists, err := webhookClient.Exists(ctx, owner, repo, rs.Status.WebhookID)
		if err != nil || !exists {
			// Re-register if gone
			hookID, err := webhookClient.Register(ctx, owner, repo, rs.Spec.ListenerURL, hmac)
			if err != nil {
				return r.failWith(ctx, rs, conditionTypeWebhook, "WebhookReRegistrationFailed", err)
			}
			rs.Status.WebhookID = hookID
			log.Info("Webhook re-registered", "hookID", hookID)
		}
	}

	meta.SetStatusCondition(&rs.Status.Conditions, metav1.Condition{
		Type:               conditionTypeWebhook,
		Status:             metav1.ConditionTrue,
		Reason:             "WebhookRegistered",
		Message:            fmt.Sprintf("Webhook registered with ID %d", rs.Status.WebhookID),
		ObservedGeneration: rs.Generation,
	})

	// -------------------------------------------------------------------------
	// Inject workflow file
	// -------------------------------------------------------------------------
	if rs.Spec.Webhook.Inject && !rs.Status.WorkflowInjected {
		workflowClient := workflow.NewClient(ctx, pat)

		if err := workflowClient.Inject(ctx, owner, repo, rs.Spec.Webhook.WorkflowPath); err != nil {
			return r.failWith(ctx, rs, conditionTypeWorkflow, "WorkflowInjectionFailed", err)
		}

		// Register BLANKETOPS_LISTENER_URL as repo secret
		if err := workflowClient.RegisterSecret(
			ctx, owner, repo,
			"BLANKETOPS_LISTENER_URL",
			rs.Spec.ListenerURL,
		); err != nil {
			return r.failWith(ctx, rs, conditionTypeWorkflow, "ListenerURLSecretFailed", err)
		}

		rs.Status.WorkflowInjected = true
		rs.Status.ListenerURLRegistered = true
		log.Info("Workflow injected", "path", rs.Spec.Webhook.WorkflowPath)
	}

	meta.SetStatusCondition(&rs.Status.Conditions, metav1.Condition{
		Type:               conditionTypeWorkflow,
		Status:             metav1.ConditionTrue,
		Reason:             "WorkflowInjected",
		Message:            fmt.Sprintf("Workflow injected at %s", rs.Spec.Webhook.WorkflowPath),
		ObservedGeneration: rs.Generation,
	})

	// -------------------------------------------------------------------------
	// Set phase → Ready
	// -------------------------------------------------------------------------
	rs.Status.Phase = phaseReady
	rs.Status.ObservedGeneration = rs.Generation

	meta.SetStatusCondition(&rs.Status.Conditions, metav1.Condition{
		Type:               conditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		Message:            fmt.Sprintf("RepositorySource %s is ready", rs.Name),
		ObservedGeneration: rs.Generation,
	})

	return ctrl.Result{}, r.Status().Update(ctx, rs)
}

// -------------------------------------------------------------------------
// reconcileDelete — remove webhook on CR deletion
// -------------------------------------------------------------------------
func (r *RepositorySourceReconciler) reconcileDelete(
	ctx context.Context,
	log logr.Logger,
	rs *supplychainv1alpha1.RepositorySource,
) (ctrl.Result, error) {
	if rs.Status.WebhookID != 0 {
		pat, err := r.fetchSecret(ctx, rs.Namespace, rs.Spec.TokenSecretRef, "token")
		if err == nil {
			owner, repo, err := parseRepository(rs.Spec.Repository)
			if err == nil {
				webhookClient := webhook.NewClient(ctx, pat)
				if err := webhookClient.Delete(ctx, owner, repo, rs.Status.WebhookID); err != nil {
					log.Error(err, "Failed to delete webhook", "hookID", rs.Status.WebhookID)
				} else {
					log.Info("Webhook deleted", "hookID", rs.Status.WebhookID)
				}
			}
		}
	}

	controllerutil.RemoveFinalizer(rs, repositorySourceFinalizer)
	return ctrl.Result{}, r.Update(ctx, rs)
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------
func (r *RepositorySourceReconciler) fetchSecret(
	ctx context.Context,
	namespace, secretName, key string,
) (string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: namespace,
	}, secret); err != nil {
		return "", fmt.Errorf("fetching secret %s: %w", secretName, err)
	}

	val, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s", key, secretName)
	}

	return string(val), nil
}

func (r *RepositorySourceReconciler) failWith(
	ctx context.Context,
	rs *supplychainv1alpha1.RepositorySource,
	condType, reason string,
	err error,
) (ctrl.Result, error) {
	rs.Status.Phase = phaseFailed
	meta.SetStatusCondition(&rs.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            err.Error(),
		ObservedGeneration: rs.Generation,
	})
	_ = r.Status().Update(ctx, rs)
	return ctrl.Result{}, err
}

func parseRepository(repository string) (string, string, error) {
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repository format %q, expected owner/repo", repository)
	}
	return parts[0], parts[1], nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RepositorySourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&supplychainv1alpha1.RepositorySource{}).
		Named("repositorysource").
		Complete(r)
}
