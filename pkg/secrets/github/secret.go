package github

import (
	"context"
	"reflect"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/ntlaletsi70/blanketops-environments-supply-chain/api/v1alpha1"
)

type GitHubPATSecretReconciler struct {
	Client client.Client
	Log    logr.Logger
}

func NewGitHubPATSecretReconciler(
	c client.Client,
	log logr.Logger,
) *GitHubPATSecretReconciler {
	return &GitHubPATSecretReconciler{
		Client: c,
		Log:    log,
	}
}

func (r *GitHubPATSecretReconciler) Reconcile(
	ctx context.Context,
	rs *supplyv1alpha1.RepositorySource,
) error {
	secretName := rs.Spec.TokenSecretRef
	if secretName == "" {
		return nil
	}

	namespace := rs.Namespace

	// -------------------------------------------------------------------------
	// Desired ExternalSecret
	// -------------------------------------------------------------------------
	desired := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "external-secrets.io/v1",
			"kind":       "ExternalSecret",
			"metadata": map[string]any{
				"name":      secretName,
				"namespace": namespace,
				"labels": map[string]any{
					"blanketops.dev/managed":           "true",
					"blanketops.dev/purpose":           "github-pat",
					"blanketops.dev/repository-source": rs.Name,
				},
			},
			"spec": map[string]any{
				"refreshInterval": "0s",
				"secretStoreRef": map[string]any{
					"name": "blanketops-supply-chain-store",
					"kind": "ClusterSecretStore",
				},
				"target": map[string]any{
					"name": secretName,
					"template": map[string]any{
						"type": "Opaque",
					},
				},
				"data": []any{
					map[string]any{
						"secretKey": "token",
						"remoteRef": map[string]any{
							"key": "/supplychain/github/pat",
						},
					},
				},
			},
		},
	}

	// -------------------------------------------------------------------------
	// Ownership (RepositorySource → ExternalSecret)
	// -------------------------------------------------------------------------
	if err := controllerutil.SetControllerReference(
		rs,
		desired,
		r.Client.Scheme(),
	); err != nil {
		return err
	}

	// -------------------------------------------------------------------------
	// Fetch existing
	// -------------------------------------------------------------------------
	var existing unstructured.Unstructured
	existing.SetGroupVersionKind(desired.GroupVersionKind())

	err := r.Client.Get(
		ctx,
		client.ObjectKey{
			Name:      secretName,
			Namespace: namespace,
		},
		&existing,
	)

	// -------------------------------------------------------------------------
	// Create
	// -------------------------------------------------------------------------
	if apierrors.IsNotFound(err) {
		r.Log.Info(
			"Creating ExternalSecret for GitHub PAT",
			"repository-source", rs.Name,
			"secret", secretName,
		)
		return r.Client.Create(ctx, desired)
	}

	if err != nil {
		return err
	}

	// -------------------------------------------------------------------------
	// Update (spec drift only)
	// -------------------------------------------------------------------------
	if !reflect.DeepEqual(
		existing.Object["spec"],
		desired.Object["spec"],
	) {
		existing.Object["spec"] = desired.Object["spec"]
		r.Log.Info(
			"Updating ExternalSecret for GitHub PAT",
			"repository-source", rs.Name,
			"secret", secretName,
		)
		return r.Client.Update(ctx, &existing)
	}

	// -------------------------------------------------------------------------
	// No-op
	// -------------------------------------------------------------------------
	r.Log.V(1).Info(
		"ExternalSecret for GitHub PAT already up-to-date",
		"repository-source", rs.Name,
		"secret", secretName,
	)

	return nil
}
