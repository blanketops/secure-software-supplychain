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

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	triggersv1beta1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/authz"
	registry "github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/registry"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/tekton/events"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/tekton/triggers"
)

const (
	supplyChainFinalizer = "supplychain.blanketops.dev/finalizer"

	phaseUnauthorized = "Unauthorized"

	// unauthorizedRetry is how soon a denied ServiceAccount is reviewed again.
	unauthorizedRetry = 30 * time.Second
	// authorizationRecheck is how often a registered identity is reviewed,
	// and so how long it can outlive the permissions it was granted on.
	authorizationRecheck = 5 * time.Minute
)

// SupplyChainReconciler reconciles a SupplyChain object
type SupplyChainReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychains,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychains/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychains/finalizers,verbs=update
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuildresults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=imagebuildresults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tekton.dev,resources=tasks;pipelineruns;pipelines;taskruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.tekton.dev,resources=eventlisteners;triggerbindings;triggertemplates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=external-secrets.io,resources=externalsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts;secrets;events;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
// +kubebuilder:rbac:groups=spire.spiffe.io,resources=clusterstaticentries,verbs=get;create;update;patch;delete

func (r *SupplyChainReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues(
		"controller", "supplychain",
		"namespace", req.Namespace,
		"name", req.Name,
	)

	var sc supplyv1alpha1.SupplyChain
	if err := r.Get(ctx, req.NamespacedName, &sc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !sc.DeletionTimestamp.IsZero() {
		logger.Info("handling deletion")
		return r.handleDeletion(ctx, &sc)
	}

	if !controllerutil.ContainsFinalizer(&sc, supplyChainFinalizer) {
		logger.Info("adding finalizer")
		controllerutil.AddFinalizer(&sc, supplyChainFinalizer)
		if err := r.Update(ctx, &sc); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if err := r.enforceRepoUniqueness(ctx, &sc); err != nil {
		logger.Error(err, "repo uniqueness violation", "repository", sc.Spec.Repository)
		return r.setPhase(ctx, &sc, "Error", err)
	}

	if err := r.reconcileTasks(ctx, &sc); err != nil {
		logger.Error(err, "failed to reconcile tasks")
		return r.setPhase(ctx, &sc, "Degraded", err)
	}

	// ── ServiceAccount ────────────────────────────────────────────────────
	// Must exist before the EventListener deployment uses it.
	// Owned by the SupplyChain — not by individual ImageBuilds.
	saName := runnerServiceAccount(&sc)
	if err := r.ensureServiceAccount(ctx, &sc, saName); err != nil {
		logger.Error(err, "failed to ensure ServiceAccount", "name", saName)
		return r.setPhase(ctx, &sc, "Degraded", err)
	}
	logger.Info("ServiceAccount ready", "name", saName)

	// ── Signing identity ──────────────────────────────────────────────────
	// Under SPIFFE the runner's identity is registered here, by the authority,
	// so it exists before any build pod asks for it.
	authorized, err := r.ensureSigningIdentity(ctx, &sc, saName)
	if err != nil {
		logger.Error(err, "Failed to register signing identity", "serviceAccount", saName)
		return r.setPhase(ctx, &sc, "Degraded", err)
	}
	if !authorized {
		// Nothing below is of use to a ServiceAccount that may not build, and
		// it has no identity to sign with. RBAC is not watched; look again.
		logger.Info("Build ServiceAccount is not authorized; signing identity withheld", "serviceAccount", saName)
		sc.Status.Phase = phaseUnauthorized
		if err := r.Status().Update(ctx, &sc); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: unauthorizedRetry}, nil
	}

	// ── Trigger layer ─────────────────────────────────────────────────────
	if err := triggers.EnsureTriggerBinding(ctx, r.Client, sc.Namespace, sc.Name); err != nil {
		logger.Error(err, "failed to reconcile TriggerBinding")
		return r.setPhase(ctx, &sc, "Degraded", err)
	}

	if err := triggers.EnsureTriggerTemplate(ctx, r.Client, sc.Namespace, sc.Name); err != nil {
		logger.Error(err, "failed to reconcile TriggerTemplate")
		return r.setPhase(ctx, &sc, "Degraded", err)
	}

	if err := events.EnsureEventListener(ctx, r.Client, r.Scheme, &sc, saName); err != nil {
		logger.Error(err, "failed to reconcile EventListener")
		return r.setPhase(ctx, &sc, "Degraded", err)
	}

	logger.Info("trigger layer reconciled",
		"triggerBinding", fmt.Sprintf("secure-software-supplychain-github-binding-%s", sc.Name),
		"triggerTemplate", fmt.Sprintf("secure-software-supplychain-imagebuild-template-%s", sc.Name),
		"eventListener", "secure-software-supplychain-eventlistener",
	)

	sc.Status.Phase = "Ready"
	if err := r.Status().Update(ctx, &sc); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("SupplyChain ready", "repository", sc.Spec.Repository)
	if sc.Status.SigningIdentity != "" {
		// The identity stays registered only while the proofs hold.
		return ctrl.Result{RequeueAfter: authorizationRecheck}, nil
	}
	return ctrl.Result{}, nil
}

// ensureServiceAccount ensures the pipeline runner SA exists before the
// EventListener deployment tries to use it, and that it carries the registry
// credentials Tekton Chains needs.
//
// Chains signs and attests what a run produced using the registry credentials
// of the run's ServiceAccount. The "<registrySecret>-chains" pull secret is
// synced for that purpose; without it on the ServiceAccount Chains cannot
// store anything next to the image.
func (r *SupplyChainReconciler) ensureServiceAccount(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	name string,
) error {
	logger := log.FromContext(ctx)

	var pullSecrets []corev1.LocalObjectReference
	if sc.Spec.Image.RegistrySecretRef != "" {
		pullSecrets = append(pullSecrets, corev1.LocalObjectReference{
			Name: registry.ChainsSecretName(sc.Spec.Image.RegistrySecretRef),
		})
	}

	var existing corev1.ServiceAccount
	err := r.Get(ctx, client.ObjectKey{Namespace: sc.Namespace, Name: name}, &existing)
	if apierrors.IsNotFound(err) {
		logger.Info("Creating ServiceAccount", "name", name)
		return r.Create(ctx, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: sc.Namespace,
				Labels: map[string]string{
					"blanketops.dev/managed":      "true",
					"blanketops.dev/supply-chain": sc.Name,
				},
			},
			ImagePullSecrets: pullSecrets,
		})
	}
	if err != nil {
		return err
	}

	// The ServiceAccount may predate this, or have been created by hand; add
	// what is missing and leave anything else on it alone.
	changed := false
	for _, want := range pullSecrets {
		found := false
		for _, have := range existing.ImagePullSecrets {
			if have.Name == want.Name {
				found = true
				break
			}
		}
		if !found {
			existing.ImagePullSecrets = append(existing.ImagePullSecrets, want)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	logger.Info("Adding registry credentials to ServiceAccount", "name", name)
	return r.Update(ctx, &existing)
}

func runnerServiceAccount(sc *supplyv1alpha1.SupplyChain) string {
	if sc.Spec.ServiceAccountName != "" {
		return sc.Spec.ServiceAccountName
	}
	return "supply-chain-runner"
}

// ensureSigningIdentity reviews the build ServiceAccount and, when the cluster
// signs with SPIFFE identities, registers its identity with SPIRE only while
// all three authorization checks pass. It reports whether the ServiceAccount
// may sign.
//
// SPIRE hands a registered identity to any pod that runs as the
// ServiceAccount, and Fulcio turns it into a signing certificate. Registering
// it is therefore the point at which the authorization has to hold: without
// the proofs there is no identity, and without an identity Fulcio issues
// nothing.
//
// Under the Kubernetes identity the ServiceAccount token is the identity and
// there is nothing to register or withhold; the proofs are recorded and every
// build is still reviewed before it starts.
func (r *SupplyChainReconciler) ensureSigningIdentity(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	saName string,
) (bool, error) {
	identity, err := signing.LoadIdentity(ctx, r.Client)
	if err != nil {
		return false, err
	}

	proofs, denied := signing.AuthorizeSigner(ctx, r.Client, sc.Namespace, saName)
	sc.Status.Authorization = &supplyv1alpha1.SignerAuthorization{
		Scope:  authorizationProof(proofs.Scope),
		Intent: authorizationProof(proofs.Intent),
		Output: authorizationProof(proofs.Output),
	}
	sc.Status.SigningIdentity = ""
	if proofs.Scope == nil || proofs.Intent == nil || proofs.Output == nil {
		// The API server did not answer. That is not a denial: leave the
		// registration as it is and try again.
		return false, fmt.Errorf("reviewing ServiceAccount %s: %w", saName, denied)
	}
	if !identity.IsSPIFFE() {
		return true, nil
	}

	if denied != nil {
		if err := r.deleteSigningIdentity(ctx, sc.Namespace, saName); err != nil {
			return false, err
		}
		return false, nil
	}

	entry := signing.WorkloadEntry(identity, sc.Namespace, saName)
	err = r.Apply(ctx, client.ApplyConfigurationFromUnstructured(entry),
		client.ForceOwnership, client.FieldOwner("supplychain-controller"))
	if err != nil {
		return false, fmt.Errorf("registering SPIFFE identity %s: %w", identity.Subject(sc.Namespace, saName), err)
	}
	sc.Status.SigningIdentity = identity.Subject(sc.Namespace, saName)
	return true, nil
}

func authorizationProof(proof *authz.AuthzProof) *supplyv1alpha1.AuthorizationProof {
	if proof == nil {
		return nil
	}
	return &supplyv1alpha1.AuthorizationProof{
		Principal:   proof.Principal,
		Group:       proof.Group,
		Resource:    proof.Resource,
		Verb:        proof.Verb,
		Allowed:     proof.Allowed,
		Reason:      proof.Reason,
		EvaluatedAt: metav1.NewTime(proof.EvaluatedAt),
	}
}

// releaseSigningIdentity removes the runner's SPIRE registration unless
// another SupplyChain in the namespace builds with the same ServiceAccount.
func (r *SupplyChainReconciler) releaseSigningIdentity(ctx context.Context, sc *supplyv1alpha1.SupplyChain) error {
	saName := runnerServiceAccount(sc)

	var list supplyv1alpha1.SupplyChainList
	if err := r.List(ctx, &list, client.InNamespace(sc.Namespace)); err != nil {
		return err
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name != sc.Name && other.DeletionTimestamp.IsZero() && runnerServiceAccount(other) == saName {
			return nil
		}
	}

	return r.deleteSigningIdentity(ctx, sc.Namespace, saName)
}

func (r *SupplyChainReconciler) deleteSigningIdentity(ctx context.Context, namespace, saName string) error {
	entry := &unstructured.Unstructured{}
	entry.SetGroupVersionKind(signing.ClusterStaticEntryGVK)
	entry.SetName(signing.WorkloadEntryName(namespace, saName))
	err := r.Delete(ctx, entry)
	// No SPIRE in this cluster means there was never anything to remove.
	if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
		return nil
	}
	return err
}

func (r *SupplyChainReconciler) reconcileTasks(ctx context.Context, sc *supplyv1alpha1.SupplyChain) error {
	logger := log.FromContext(ctx)
	for _, desired := range customTasks(sc.Namespace) {
		task := desired
		result, err := controllerutil.CreateOrUpdate(ctx, r.Client, &task, func() error {
			task.Spec = desired.Spec
			return nil
		})
		if err != nil {
			return fmt.Errorf("reconciling Task %q: %w", task.Name, err)
		}
		logger.Info("task reconciled", "task", task.Name, "result", result)
	}
	return nil
}

func customTasks(namespace string) []tektonv1.Task {
	return []tektonv1.Task{
		sonarQubeTask(namespace),
		cosignSignTask(namespace),
		tektonChainsAttestTask(namespace),
	}
}

func sonarQubeTask(namespace string) tektonv1.Task {
	return tektonv1.Task{
		ObjectMeta: metav1.ObjectMeta{Name: "sonarqube-scanner", Namespace: namespace},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{Name: "SONAR_HOST_URL", Type: tektonv1.ParamTypeString, Description: "SonarQube server URL"},
				{Name: "SONAR_PROJECT_KEY", Type: tektonv1.ParamTypeString, Description: "SonarQube project key"},
				{Name: "SONAR_TOKEN_SECRET", Type: tektonv1.ParamTypeString, Description: "Secret name containing the SonarQube token",
					Default: &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "sonarqube-token"}},
			},
			Steps: []tektonv1.Step{{
				Name:  "sonar-scan",
				Image: "sonarsource/sonar-scanner-cli:latest",
				Env: []corev1.EnvVar{{
					Name: "SONAR_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "$(params.SONAR_TOKEN_SECRET)"},
							Key:                  "token",
						},
					},
				}},
				Args: []string{
					"-Dsonar.host.url=$(params.SONAR_HOST_URL)",
					"-Dsonar.projectKey=$(params.SONAR_PROJECT_KEY)",
					"-Dsonar.login=$(SONAR_TOKEN)",
				},
			}},
		},
	}
}

func cosignSignTask(namespace string) tektonv1.Task {
	return tektonv1.Task{
		ObjectMeta: metav1.ObjectMeta{Name: "cosign-sign", Namespace: namespace},
		Spec: tektonv1.TaskSpec{
			Params: []tektonv1.ParamSpec{
				{Name: "IMAGE", Type: tektonv1.ParamTypeString, Description: "Image reference to sign"},
				{Name: "FULCIO_URL", Type: tektonv1.ParamTypeString, Description: "Fulcio CA URL",
					Default: &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "https://fulcio.sigstore.dev"}},
				{Name: "REKOR_URL", Type: tektonv1.ParamTypeString, Description: "Rekor transparency log URL",
					Default: &tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "https://rekor.sigstore.dev"}},
			},
			Steps: []tektonv1.Step{{
				Name:  "sign",
				Image: "gcr.io/projectsigstore/cosign:v2.2.3",
				Env:   []corev1.EnvVar{{Name: "COSIGN_EXPERIMENTAL", Value: "1"}},
				Args: []string{
					"sign",
					"--fulcio-url=$(params.FULCIO_URL)",
					"--rekor-url=$(params.REKOR_URL)",
					"--yes",
					"$(params.IMAGE)",
				},
			}},
		},
	}
}

func tektonChainsAttestTask(namespace string) tektonv1.Task {
	return tektonv1.Task{
		ObjectMeta: metav1.ObjectMeta{Name: "tekton-chains-attest", Namespace: namespace},
		Spec: tektonv1.TaskSpec{
			Params:  []tektonv1.ParamSpec{{Name: "IMAGE", Type: tektonv1.ParamTypeString, Description: "Image reference to attest"}},
			Results: []tektonv1.TaskResult{{Name: "IMAGE_URL", Type: tektonv1.ResultsTypeString}, {Name: "IMAGE_DIGEST", Type: tektonv1.ResultsTypeString}},
			Steps: []tektonv1.Step{{
				Name:  "attest",
				Image: "gcr.io/go-containerregistry/crane:latest",
				Script: `#!/bin/sh
set -e
digest=$(crane digest $(params.IMAGE))
echo -n "$(params.IMAGE)" | tee $(results.IMAGE_URL.path)
echo -n "${digest}" | tee $(results.IMAGE_DIGEST.path)`,
			}},
		},
	}
}

func (r *SupplyChainReconciler) enforceRepoUniqueness(ctx context.Context, sc *supplyv1alpha1.SupplyChain) error {
	var list supplyv1alpha1.SupplyChainList
	if err := r.List(ctx, &list, client.InNamespace(sc.Namespace)); err != nil {
		return err
	}
	for _, existing := range list.Items {
		if existing.Name == sc.Name {
			continue
		}
		if existing.Spec.Repository == sc.Spec.Repository {
			return fmt.Errorf("repository %q is already claimed by SupplyChain %q — one SupplyChain per repository is law",
				sc.Spec.Repository, existing.Name)
		}
	}
	return nil
}

func (r *SupplyChainReconciler) handleDeletion(ctx context.Context, sc *supplyv1alpha1.SupplyChain) (ctrl.Result, error) {
	if err := r.releaseSigningIdentity(ctx, sc); err != nil {
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(sc, supplyChainFinalizer)
	if err := r.Update(ctx, sc); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *SupplyChainReconciler) setPhase(ctx context.Context, sc *supplyv1alpha1.SupplyChain, phase string, cause error) (ctrl.Result, error) {
	sc.Status.Phase = phase
	_ = r.Status().Update(ctx, sc)
	if cause != nil {
		return ctrl.Result{}, cause
	}
	return ctrl.Result{}, nil
}

func (r *SupplyChainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&supplyv1alpha1.SupplyChain{}).
		Owns(&supplyv1alpha1.ImageBuild{}).
		Owns(&networkingv1.Ingress{}).
		Owns(&tektonv1.Task{}).
		Owns(&tektonv1.PipelineRun{}).
		Owns(&tektonv1.TaskRun{}).
		Owns(&tektonv1.Pipeline{}).
		Owns(&triggersv1beta1.EventListener{}).
		Owns(&triggersv1beta1.TriggerBinding{}).
		Owns(&triggersv1beta1.TriggerTemplate{}).
		// The signing identity comes from Chains' and Tekton's SPIRE config;
		// when either changes, every SupplyChain's registration is revisited.
		Watches(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.supplyChainsForSigningConfig),
			builder.WithPredicates(predicate.NewPredicateFuncs(isSigningConfig))).
		Complete(r)
}

func isSigningConfig(obj client.Object) bool {
	key := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
	return key == types.NamespacedName{Namespace: signing.ChainsConfigNamespace, Name: signing.ChainsConfigName} ||
		key == types.NamespacedName{Namespace: signing.SpireConfigNamespace, Name: signing.SpireConfigName}
}

func (r *SupplyChainReconciler) supplyChainsForSigningConfig(ctx context.Context, _ client.Object) []reconcile.Request {
	var list supplyv1alpha1.SupplyChainList
	if err := r.List(ctx, &list); err != nil {
		log.FromContext(ctx).Error(err, "Failed to list SupplyChains")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return requests
}
