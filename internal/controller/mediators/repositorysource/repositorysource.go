package repositorysource

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplychainv1alpha1 "github.com/ntlaletsi70/blanketops-environments-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/blanketops-environments-supply-chain/pkg/secrets/github"
)

type Mediator struct {
	Client   client.Client
	Scheme   *runtime.Scheme
	Log      logr.Logger
	Recorder record.EventRecorder

	GitHubPATSecretReconciler *github.GitHubPATSecretReconciler
}

func New(
	c client.Client,
	scheme *runtime.Scheme,
	log logr.Logger,
	recorder record.EventRecorder,
) *Mediator {
	return &Mediator{
		Client:                    c,
		Scheme:                    scheme,
		Log:                       log,
		Recorder:                  recorder,
		GitHubPATSecretReconciler: github.NewGitHubPATSecretReconciler(c, log),
	}
}

func (m *Mediator) EnsurePrerequisites(
	ctx context.Context,
	rs *supplychainv1alpha1.RepositorySource,
	sc *supplychainv1alpha1.SupplyChain,
) (bool, error) {

	log := m.Log.WithValues(
		"supply-chain", sc.Name,
		"repository-source", rs.Name,
		"namespace", rs.Namespace,
	)

	log.Info("mediator start")

	// -------------------------------------------------
	// 1. Intent: ExternalSecrets
	// -------------------------------------------------

	log.Info("reconciling GitHub PAT ExternalSecret")
	if err := m.GitHubPATSecretReconciler.Reconcile(ctx, rs); err != nil {
		log.Error(err, "GitHub PAT secret reconcile failed")
		m.recordWarning(rs, "GitHubPATSecretFailed", err)
		return false, fmt.Errorf("GitHub PAT secret: %w", err)
	}

	// -------------------------------------------------
	// 2. Convergence: wait for secrets
	// -------------------------------------------------

	githubSecretName := rs.Spec.TokenSecretRef

	if !m.secretExists(ctx, githubSecretName, rs.Namespace) {
		log.Info("GitHub PAT secret not ready yet", "secret", githubSecretName)
		return false, nil
	}

	log.Info("secrets ready — reconciling ServiceAccount")

	// -------------------------------------------------
	// 3. Identity: ensure ServiceAccount
	// -------------------------------------------------

	if err := m.ensureServiceAccount(ctx, sc, rs); err != nil {
		log.Error(err, "failed to reconcile ServiceAccount")
		m.recordWarning(rs, "ServiceAccountFailed", err)
		return false, err
	}

	// -------------------------------------------------
	// READY
	// -------------------------------------------------

	log.Info("mediator ready — prerequisites converged")

	return true, nil
}

func (m *Mediator) ensureServiceAccount(
	ctx context.Context,
	sc *supplychainv1alpha1.SupplyChain,
	ib *supplychainv1alpha1.RepositorySource,
) error {

	name := sc.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}

	desired := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ib.Namespace,
			Labels: map[string]string{
				"blanketops.dev/managed":      "true",
				"blanketops.dev/supply-chain": sc.Name,
			},
		},
		Secrets: []corev1.ObjectReference{
			{Name: "github-ssh-credentials"},
			{Name: "docker-registry-credentials"},
			{Name: "sonarqube-credentials"},
		},
	}

	if err := controllerutil.SetControllerReference(ib, desired, m.Scheme); err != nil {
		return err
	}

	var existing corev1.ServiceAccount
	err := m.Client.Get(ctx, client.ObjectKeyFromObject(desired), &existing)

	if apierrors.IsNotFound(err) {
		m.Log.Info("creating ServiceAccount", "name", name)
		return m.Client.Create(ctx, desired)
	}

	if err != nil {
		return err
	}

	if !reflect.DeepEqual(existing.Secrets, desired.Secrets) {
		existing.Secrets = desired.Secrets
		m.Log.Info("updating ServiceAccount secrets", "name", name)
		return m.Client.Update(ctx, &existing)
	}

	return nil
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
	rs *supplychainv1alpha1.RepositorySource,
	reason string,
	err error,
) {
	if m.Recorder != nil {
		m.Recorder.Event(
			rs,
			corev1.EventTypeWarning,
			reason,
			err.Error(),
		)
	}
}
