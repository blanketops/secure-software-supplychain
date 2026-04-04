package supplychain

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/ntlaletsi70/blanketops-environments-supply-chain/api/v1alpha1"
	git "github.com/ntlaletsi70/blanketops-environments-supply-chain/pkg/secrets/git"
	registry "github.com/ntlaletsi70/blanketops-environments-supply-chain/pkg/secrets/registry"
	sonarqube "github.com/ntlaletsi70/blanketops-environments-supply-chain/pkg/secrets/sonarqube"
)

type Mediator struct {
	Client                           client.Client
	Scheme                           *runtime.Scheme
	Log                              logr.Logger
	Recorder                         record.EventRecorder
	GitSSHExternalSecretReconciler   *git.GitSSHSecretReconciler
	RegistryExternalSecretReconciler *registry.RegistrySecretReconciler

	SonarQubeExternalSecretReconciler *sonarqube.SonarQubeSecretReconciler
}

func New(
	c client.Client,
	scheme *runtime.Scheme,
	log logr.Logger,
	recorder record.EventRecorder,
) *Mediator {
	return &Mediator{
		Client:                            c,
		Scheme:                            scheme,
		Log:                               log,
		Recorder:                          recorder,
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

	log.Info("secrets ready — reconciling ServiceAccount")

	// -------------------------------------------------
	// 3. Identity: ensure ServiceAccount
	// -------------------------------------------------

	if err := m.ensureServiceAccount(ctx, sc, ib); err != nil {
		log.Error(err, "failed to reconcile ServiceAccount")
		m.recordWarning(ib, "ServiceAccountFailed", err)
		return false, err
	}

	// -------------------------------------------------
	// 4. Authorization: SubjectAccessReview
	// -------------------------------------------------
	if err := m.verifySigningPermission(ctx, sc, ib); err != nil {
		log.Error(err, "signing permission denied")
		m.recordWarning(ib, "SigningPermissionDenied", err)
		return false, err
	}

	// -------------------------------------------------
	// READY
	// -------------------------------------------------

	log.Info("mediator ready — prerequisites converged")

	return true, nil
}

func (m *Mediator) verifySigningPermission(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
) error {
	saName := sc.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}

	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: fmt.Sprintf("system:serviceaccount:%s:%s", ib.Namespace, saName),
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: ib.Namespace,
				Verb:      "create",
				Group:     "supplychain.blanketops.dev",
				Resource:  "imagesignatures",
			},
		},
	}

	if err := m.Client.Create(ctx, sar); err != nil {
		return fmt.Errorf("SubjectAccessReview failed: %w", err)
	}

	if !sar.Status.Allowed {
		return fmt.Errorf(
			"SA %s is not permitted to sign images: %s",
			saName,
			sar.Status.Reason,
		)
	}

	m.Log.Info("signing permission granted",
		"serviceAccount", saName,
		"namespace", ib.Namespace,
	)

	return nil
}

func (m *Mediator) ensureServiceAccount(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
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
			{Name: sc.Spec.Image.CloneSecretRef},
			{Name: sc.Spec.Image.RegistrySecretRef},
			{Name: sc.Spec.Steps.SonarQube.TokenSecretRef},
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
