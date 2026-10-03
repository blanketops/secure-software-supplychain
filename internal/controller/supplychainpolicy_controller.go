/*
Copyright 2026.

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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/policy"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

const (
	supplyChainPolicyFinalizer = "supplychain.blanketops.dev/policy-finalizer"

	conditionReady = "Ready"

	// policyControllerRetry is how long to wait before looking for the
	// policy-controller CRDs again. They cannot be watched before they exist.
	policyControllerRetry = time.Minute
)

// SupplyChainPolicyReconciler reconciles a SupplyChainPolicy object
type SupplyChainPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychainpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychainpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychainpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=supplychain.blanketops.dev,resources=supplychains,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy.sigstore.dev,resources=clusterimagepolicies;trustroots,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile renders the policy-controller TrustRoot and ClusterImagePolicies for
// a SupplyChainPolicy from the SupplyChain it references and the sigstore
// trust anchors in its namespace.
func (r *SupplyChainPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var scp supplychainv1alpha1.SupplyChainPolicy
	if err := r.Get(ctx, req.NamespacedName, &scp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !scp.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, &scp)
	}

	if controllerutil.AddFinalizer(&scp, supplyChainPolicyFinalizer) {
		if err := r.Update(ctx, &scp); err != nil {
			return ctrl.Result{}, err
		}
	}

	var sc supplychainv1alpha1.SupplyChain
	key := types.NamespacedName{Namespace: scp.Namespace, Name: scp.Spec.SupplyChainRef.Name}
	if err := r.Get(ctx, key, &sc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.notReady(ctx, &scp, "SupplyChainNotFound",
				fmt.Sprintf("SupplyChain %q not found", key.Name))
		}
		return ctrl.Result{}, err
	}
	if !sc.Spec.Steps.Sign {
		// Enforcing a signature nobody produces would only block the workload.
		if err := r.deleteRendered(ctx, &scp); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, r.notReady(ctx, &scp, "SigningDisabled",
			fmt.Sprintf("SupplyChain %q does not sign its images", sc.Name))
	}

	var roots corev1.ConfigMap
	key = types.NamespacedName{Namespace: scp.Namespace, Name: signing.RootsConfigMap}
	if err := r.Get(ctx, key, &roots); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.notReady(ctx, &scp, "TrustAnchorsNotFound",
				fmt.Sprintf("ConfigMap %q not found", key.Name))
		}
		return ctrl.Result{}, err
	}

	rendered, err := policy.Render(&scp, &sc, roots.Data)
	if err != nil {
		return ctrl.Result{}, r.notReady(ctx, &scp, "TrustAnchorsInvalid", err.Error())
	}

	// TrustRoot first: the ClusterImagePolicies refer to it.
	policyNames := make([]string, 0, len(rendered.ClusterImagePolicies))
	for _, desired := range append([]*unstructured.Unstructured{rendered.TrustRoot}, rendered.ClusterImagePolicies...) {
		result, err := r.apply(ctx, &scp, desired)
		if meta.IsNoMatchError(err) {
			log.Info("Could not find policy-controller CRDs", "kind", desired.GetKind())
			return ctrl.Result{RequeueAfter: policyControllerRetry}, r.notReady(ctx, &scp,
				"PolicyControllerNotInstalled", "policy.sigstore.dev CRDs are not installed")
		}
		if err != nil {
			_ = r.notReady(ctx, &scp, "ApplyFailed", err.Error())
			return ctrl.Result{}, err
		}
		if result != controllerutil.OperationResultNone {
			log.Info("Applied policy resource", "kind", desired.GetKind(), "name", desired.GetName(), "result", result)
		}
	}

	for _, p := range rendered.ClusterImagePolicies {
		policyNames = append(policyNames, p.GetName())
	}
	scp.Status.TrustRoot = rendered.TrustRoot.GetName()
	scp.Status.ClusterImagePolicies = policyNames
	scp.Status.Images = rendered.Images
	scp.Status.Signers = rendered.Signers
	scp.Status.FulcioURL = rendered.Endpoints.FulcioURL
	scp.Status.RekorURL = rendered.Endpoints.RekorURL
	scp.Status.CTLogURL = rendered.Endpoints.CTLogURL
	return ctrl.Result{}, r.setReady(ctx, &scp, metav1.ConditionTrue, "PolicyApplied",
		"TrustRoot and ClusterImagePolicies are in sync with the SupplyChain")
}

// apply creates or updates one rendered resource. It refuses to touch a
// resource of the same name that belongs to something else.
func (r *SupplyChainPolicyReconciler) apply(
	ctx context.Context,
	scp *supplychainv1alpha1.SupplyChainPolicy,
	desired *unstructured.Unstructured,
) (controllerutil.OperationResult, error) {
	obj := emptyLike(desired)
	return controllerutil.CreateOrUpdate(ctx, r.Client, obj, func() error {
		if obj.GetResourceVersion() != "" && !policy.OwnedBy(obj, scp) {
			return fmt.Errorf("%s %q exists and is not managed by this SupplyChainPolicy",
				desired.GetKind(), desired.GetName())
		}
		labels := obj.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		for k, v := range desired.GetLabels() {
			labels[k] = v
		}
		obj.SetLabels(labels)
		// policy-controller defaults fields on admission; leave an equal spec
		// alone so the two controllers do not fight over it.
		if obj.Object["spec"] == nil || !equality.Semantic.DeepDerivative(desired.Object["spec"], obj.Object["spec"]) {
			obj.Object["spec"] = desired.Object["spec"]
		}
		return nil
	})
}

// finalize removes the cluster-scoped resources, which garbage collection
// cannot do for a namespaced owner, then releases the SupplyChainPolicy.
func (r *SupplyChainPolicyReconciler) finalize(ctx context.Context, scp *supplychainv1alpha1.SupplyChainPolicy) error {
	if !controllerutil.ContainsFinalizer(scp, supplyChainPolicyFinalizer) {
		return nil
	}
	if err := r.deleteRendered(ctx, scp); err != nil {
		return err
	}
	controllerutil.RemoveFinalizer(scp, supplyChainPolicyFinalizer)
	return r.Update(ctx, scp)
}

func (r *SupplyChainPolicyReconciler) deleteRendered(
	ctx context.Context,
	scp *supplychainv1alpha1.SupplyChainPolicy,
) error {
	log := logf.FromContext(ctx)
	// ClusterImagePolicies first, so none references a missing TrustRoot. They
	// are found by label, which also catches any left from an older rendering.
	for _, gvk := range []schema.GroupVersionKind{policy.ClusterImagePolicyGVK, policy.TrustRootGVK} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk)
		err := r.List(ctx, list, client.MatchingLabels{
			policy.LabelPolicyNamespace: scp.Namespace,
			policy.LabelPolicyName:      scp.Name,
		})
		if meta.IsNoMatchError(err) {
			continue
		}
		if err != nil {
			return err
		}
		for i := range list.Items {
			obj := &list.Items[i]
			if err := r.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
				return err
			}
			log.Info("Deleted policy resource", "kind", gvk.Kind, "name", obj.GetName())
		}
	}
	scp.Status.TrustRoot = ""
	scp.Status.ClusterImagePolicies = nil
	scp.Status.Images = nil
	scp.Status.Signers = nil
	scp.Status.FulcioURL = ""
	scp.Status.RekorURL = ""
	scp.Status.CTLogURL = ""
	return nil
}

func (r *SupplyChainPolicyReconciler) notReady(
	ctx context.Context,
	scp *supplychainv1alpha1.SupplyChainPolicy,
	reason, message string,
) error {
	return r.setReady(ctx, scp, metav1.ConditionFalse, reason, message)
}

func (r *SupplyChainPolicyReconciler) setReady(
	ctx context.Context,
	scp *supplychainv1alpha1.SupplyChainPolicy,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	scp.Status.ObservedGeneration = scp.Generation
	meta.SetStatusCondition(&scp.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: scp.Generation,
	})
	return r.Status().Update(ctx, scp)
}

func emptyLike(desired *unstructured.Unstructured) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(desired.GroupVersionKind())
	obj.SetName(desired.GetName())
	return obj
}

// policiesInNamespace requeues the SupplyChainPolicies that depend on obj:
// those referencing a changed SupplyChain, or all of them in the namespace
// when the trust anchors change.
func (r *SupplyChainPolicyReconciler) policiesInNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	var list supplychainv1alpha1.SupplyChainPolicyList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list SupplyChainPolicies", "namespace", obj.GetNamespace())
		return nil
	}
	_, isSupplyChain := obj.(*supplychainv1alpha1.SupplyChain)
	var requests []reconcile.Request
	for i := range list.Items {
		if isSupplyChain && list.Items[i].Spec.SupplyChainRef.Name != obj.GetName() {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *SupplyChainPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	isRoots := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetName() == signing.RootsConfigMap
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&supplychainv1alpha1.SupplyChainPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&supplychainv1alpha1.SupplyChain{},
			handler.EnqueueRequestsFromMapFunc(r.policiesInNamespace),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.policiesInNamespace),
			builder.WithPredicates(isRoots)).
		Named("supplychainpolicy").
		Complete(r)
}
