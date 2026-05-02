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
package githubwebhook

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	githubsecret "github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/github"
)

// Mediator sequences the prerequisites for the GitHubWebhookReconciler.
//
// Gate 1 — ExternalSecret reconciliation (ensure the ESO resource exists)
// Gate 2 — Convergence wait (ensure the Secret has been materialised by ESO)
//
// Same pattern as the supplychain mediator — controllers stay thin,
// prerequisite logic lives here.
type Mediator struct {
	Client   client.Client
	Scheme   *runtime.Scheme
	Log      logr.Logger
	Recorder record.EventRecorder

	GitHubTokenSecretReconciler *githubsecret.GitHubTokenSecretReconciler
}

func New(
	c client.Client,
	scheme *runtime.Scheme,
	log logr.Logger,
	recorder record.EventRecorder,
) *Mediator {
	return &Mediator{
		Client:                      c,
		Scheme:                      scheme,
		Log:                         log,
		Recorder:                    recorder,
		GitHubTokenSecretReconciler: githubsecret.NewGitHubTokenSecretReconciler(c, log),
	}
}

// EnsurePrerequisites drives the two-gate prerequisite flow for a
// GitHubWebhook. Returns true when all secrets are ready.
//
// Gate 1: reconcile ExternalSecrets (idempotent create)
// Gate 2: wait for ESO to materialise the Secrets
func (m *Mediator) EnsurePrerequisites(
	ctx context.Context,
	ghw *supplyv1alpha1.GitHubWebhook,
) (bool, error) {
	log := m.Log.WithValues(
		"githubwebhook", ghw.Name,
		"namespace", ghw.Namespace,
		"repository", ghw.Spec.Repository,
	)

	log.Info("mediator start")

	// ── Gate 1: ExternalSecrets ───────────────────────────────────────────

	log.Info("reconciling GitHub token ExternalSecret")
	if err := m.GitHubTokenSecretReconciler.Reconcile(ctx, ghw); err != nil {
		log.Error(err, "GitHub token secret reconcile failed")
		m.recordWarning(ghw, "GitHubTokenSecretFailed", err)
		return false, fmt.Errorf("github token secret: %w", err)
	}

	// ── Gate 2: Convergence ───────────────────────────────────────────────

	if !m.secretExists(ctx, ghw.Spec.SecretRef.Name, ghw.Namespace) {
		log.Info("GitHub token secret not ready yet", "secret", ghw.Spec.SecretRef.Name)
		return false, nil
	}

	// Optional webhook secret — if specified, wait for it too.
	if ghw.Spec.WebhookSecretRef != nil {
		if !m.secretExists(ctx, ghw.Spec.WebhookSecretRef.Name, ghw.Namespace) {
			log.Info("webhook secret not ready yet", "secret", ghw.Spec.WebhookSecretRef.Name)
			return false, nil
		}
	}

	log.Info("mediator ready — prerequisites converged")
	return true, nil
}

// ResolveToken reads the GitHub API token from the materialised Secret.
// Call this after EnsurePrerequisites returns true.
func (m *Mediator) ResolveToken(
	ctx context.Context,
	ghw *supplyv1alpha1.GitHubWebhook,
) (string, error) {
	return m.resolveSecretKey(ctx, ghw.Namespace, ghw.Spec.SecretRef.Name, "token")
}

// ResolveWebhookSecret reads the shared webhook signing secret.
// Returns empty string if WebhookSecretRef is not set.
func (m *Mediator) ResolveWebhookSecret(
	ctx context.Context,
	ghw *supplyv1alpha1.GitHubWebhook,
) (string, error) {
	if ghw.Spec.WebhookSecretRef == nil {
		return "", nil
	}
	return m.resolveSecretKey(ctx, ghw.Namespace, ghw.Spec.WebhookSecretRef.Name, "secret")
}

// resolveSecretKey fetches a single key from a Kubernetes Secret.
func (m *Mediator) resolveSecretKey(
	ctx context.Context,
	namespace, name, key string,
) (string, error) {
	var secret corev1.Secret
	if err := m.Client.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: namespace,
	}, &secret); err != nil {
		return "", fmt.Errorf("secret %q not found: %w", name, err)
	}

	val, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %q does not contain key %q", name, key)
	}

	return string(val), nil
}

func (m *Mediator) secretExists(
	ctx context.Context,
	name string,
	namespace string,
) bool {
	var s corev1.Secret
	err := m.Client.Get(ctx, client.ObjectKey{
		Name:      name,
		Namespace: namespace,
	}, &s)
	return err == nil
}

func (m *Mediator) recordWarning(
	ghw *supplyv1alpha1.GitHubWebhook,
	reason string,
	err error,
) {
	if m.Recorder != nil {
		m.Recorder.Event(
			ghw,
			corev1.EventTypeWarning,
			reason,
			err.Error(),
		)
	}
}
