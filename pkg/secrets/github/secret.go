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
package github

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// GitHubTokenSecretReconciler ensures a GitHub API token ExternalSecret
// exists for the GitHubWebhook controller to authenticate with GitHub.
//
// The token is sourced from the ClusterSecretStore under the key
// /supplychain/github/token and materialised as an Opaque Secret with
// a single key named "token".
type GitHubTokenSecretReconciler struct {
	Client client.Client
	Log    logr.Logger
}

func NewGitHubTokenSecretReconciler(
	c client.Client,
	log logr.Logger,
) *GitHubTokenSecretReconciler {
	return &GitHubTokenSecretReconciler{
		Client: c,
		Log:    log,
	}
}

// Reconcile ensures the GitHub token ExternalSecret exists for the given
// GitHubWebhook. Called by the GitHubWebhookReconciler before the token
// is read from the Secret.
func (r *GitHubTokenSecretReconciler) Reconcile(
	ctx context.Context,
	ghw *supplyv1alpha1.GitHubWebhook,
) error {
	if ghw.Spec.SecretRef.Name == "" {
		return fmt.Errorf("spec.secretRef.name is required")
	}

	desired := newGitHubTokenExternalSecret(ghw)

	if err := controllerutil.SetControllerReference(
		ghw,
		desired,
		r.Client.Scheme(),
	); err != nil {
		return err
	}

	var existing unstructured.Unstructured
	existing.SetGroupVersionKind(desired.GroupVersionKind())

	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	if err == nil {
		// Already exists — nothing to do.
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}

	r.Log.Info("Creating ExternalSecret for GitHub token",
		"githubwebhook", ghw.Name,
		"secret", desired.GetName(),
	)

	return r.Client.Create(ctx, desired)
}

// newGitHubTokenExternalSecret builds the ExternalSecret for the GitHub
// API token. The token is stored in the ClusterSecretStore at:
//
//	/supplychain/github/token  →  key: "token"
//
// This mirrors the pattern used by registry and git SSH secrets.
func newGitHubTokenExternalSecret(ghw *supplyv1alpha1.GitHubWebhook) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "external-secrets.io/v1",
			"kind":       "ExternalSecret",
			"metadata": map[string]any{
				"name":      ghw.Spec.SecretRef.Name,
				"namespace": ghw.Namespace,
				"labels": map[string]any{
					"blanketops.dev/managed":       "true",
					"blanketops.dev/purpose":       "github-token",
					"blanketops.dev/githubwebhook": ghw.Name,
					"blanketops.dev/repository":    sanitiseLabel(ghw.Spec.Repository),
				},
				"annotations": map[string]any{
					"blanketops.dev/repository-full-name": ghw.Spec.Repository,
				},
			},
			"spec": map[string]any{
				// refreshInterval 0s — token is stable, no need to poll.
				"refreshInterval": "0s",
				"secretStoreRef": map[string]any{
					"name": "secure-software-supply-chain-store",
					"kind": "ClusterSecretStore",
				},
				"target": map[string]any{
					"name": ghw.Spec.SecretRef.Name,
					"template": map[string]any{
						"type": "Opaque",
					},
				},
				"data": []any{
					map[string]any{
						// "token" is the key the GitHubWebhookReconciler reads.
						"secretKey": "token",
						"remoteRef": map[string]any{
							// Key path in the fake store — update to match
							// your real secret store backend key.
							"key": "/supplychain/github/token",
						},
					},
				},
			},
		},
	}
}

// sanitiseLabel replaces characters invalid in Kubernetes label values.
// repo-full-name contains "/" which is not allowed — replace with "-".
func sanitiseLabel(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			result[i] = c
		} else {
			result[i] = '-'
		}
	}
	return string(result)
}
