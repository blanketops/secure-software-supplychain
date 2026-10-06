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
package supplychain

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	git "github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/git"
	registry "github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/registry"
	sonarqube "github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/sonarqube"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

type Mediator struct {
	Client   client.Client
	Scheme   *runtime.Scheme
	Log      logr.Logger
	Recorder record.EventRecorder

	GitSSHExternalSecretReconciler    *git.GitSSHSecretReconciler
	RegistryExternalSecretReconciler  *registry.RegistrySecretReconciler
	SonarQubeExternalSecretReconciler *sonarqube.SonarQubeSecretReconciler
}

func New(
	c client.Client,
	scheme *runtime.Scheme,
	log logr.Logger,
	recorder record.EventRecorder,
) *Mediator {
	return &Mediator{
		Client:   c,
		Scheme:   scheme,
		Log:      log,
		Recorder: recorder,

		GitSSHExternalSecretReconciler:    git.NewGitSSHSecretReconciler(c, log),
		RegistryExternalSecretReconciler:  registry.NewRegistrySecretReconciler(c, log),
		SonarQubeExternalSecretReconciler: sonarqube.NewSonarQubeSecretReconciler(c, log),
	}
}

func (m *Mediator) EnsurePrerequisites(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
) (bool, error) {
	log := m.Log.WithValues(
		"supply-chain", sc.Name,
		"image-build", ib.Name,
		"namespace", ib.Namespace,
	)

	log.Info("mediator start")

	// -------------------------------------------------
	// 1. Intent: ExternalSecrets
	// -------------------------------------------------
	log.Info("reconciling git SSH ExternalSecret")
	if err := m.GitSSHExternalSecretReconciler.Reconcile(ctx, sc, ib); err != nil {
		log.Error(err, "git SSH secret reconcile failed")
		m.recordWarning(ib, "GitSSHSecretFailed", err)
		return false, fmt.Errorf("git SSH secret: %w", err)
	}

	log.Info("reconciling registry ExternalSecret")
	if err := m.RegistryExternalSecretReconciler.Reconcile(ctx, sc, ib); err != nil {
		log.Error(err, "registry secret reconcile failed")
		m.recordWarning(ib, "RegistrySecretFailed", err)
		return false, fmt.Errorf("registry secret: %w", err)
	}

	log.Info("reconciling SonarQube ExternalSecret")
	if err := m.SonarQubeExternalSecretReconciler.Reconcile(ctx, sc, ib); err != nil {
		log.Error(err, "SonarQube secret reconcile failed")
		m.recordWarning(ib, "SonarQubeSecretFailed", err)
		return false, fmt.Errorf("SonarQube secret: %w", err)
	}

	// -------------------------------------------------
	// 2. Convergence: wait for secrets
	// -------------------------------------------------
	gitSecretName := sc.Spec.Image.CloneSecretRef
	registrySecretName := sc.Spec.Image.RegistrySecretRef
	sonarqubeSecretName := sc.Spec.Steps.SonarQube.TokenSecretRef

	if !m.secretExists(ctx, gitSecretName, ib.Namespace) {
		log.Info("git SSH secret not ready yet", "secret", gitSecretName)
		return false, nil
	}
	if !m.secretExists(ctx, registrySecretName, ib.Namespace) {
		log.Info("registry secret not ready yet", "secret", registrySecretName)
		return false, nil
	}
	if !m.secretExists(ctx, sonarqubeSecretName, ib.Namespace) {
		log.Info("SonarQube secret not ready yet", "secret", sonarqubeSecretName)
		return false, nil
	}

	// -------------------------------------------------
	// READY
	// -------------------------------------------------
	log.Info("mediator ready — prerequisites converged")
	return true, nil
}

// EstablishSigningContext reviews the build ServiceAccount for this run.
// Called by the controller AFTER EnsurePrerequisites returns true.
//
// Same pattern as the secret reconcilers — a separate block that the
// controller calls in sequence. Prerequisites ensure cluster state,
// signing establishes cryptographic identity for this run.
func (m *Mediator) EstablishSigningContext(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
) (*signing.RunSigningContext, error) {
	log := m.Log.WithValues(
		"supply-chain", sc.Name,
		"image-build", ib.Name,
		"namespace", ib.Namespace,
	)

	saName := sc.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}

	log.Info("establishing signing context", "serviceAccount", saName)

	sigCtx, err := signing.EstablishSigningContext(ctx, m.Client, saName, ib.Namespace)
	if err != nil {
		log.Error(err, "signing context failed")
		m.recordWarning(ib, "SigningContextFailed", err)
		return nil, err
	}

	log.Info("signing context established",
		"principal", sigCtx.ScopeProof.Principal,
		"scopeAllowed", sigCtx.ScopeProof.Allowed,
		"intentAllowed", sigCtx.IntentProof.Allowed,
		"outputAllowed", sigCtx.OutputProof.Allowed,
	)
	return sigCtx, nil
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
	ib *supplyv1alpha1.ImageBuild,
	reason string,
	err error,
) {
	if m.Recorder != nil {
		m.Recorder.Event(
			ib,
			corev1.EventTypeWarning,
			reason,
			err.Error(),
		)
	}
}
