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
	"testing"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	triggersv1beta1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	"github.com/blanketops/secure-software-supplychain/pkg/tekton/triggers"
)

func ownershipScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme, supplychainv1alpha1.AddToScheme, tektonv1.AddToScheme, triggersv1beta1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

func ownerRef(obj client.Object, uid types.UID) *metav1.OwnerReference {
	refs := obj.GetOwnerReferences()
	for i := range refs {
		if refs[i].UID == uid {
			return &refs[i]
		}
	}
	return nil
}

// Deleting a SupplyChain has to take what it made with it. Kubernetes does
// the removing, from owner references: what is the SupplyChain's alone is
// controlled by it, and what several may use lists each of them and goes with
// the last. Before this, the trigger objects, the build ServiceAccount and the
// Tasks stayed behind in the namespace.
func TestSupplyChainOwnsWhatItCreates(t *testing.T) {
	ctx := context.Background()
	scheme := ownershipScheme(t)
	first := yourAppSupplyChain("your-app")
	first.UID = "first"
	second := yourAppSupplyChain("your-other-app")
	second.UID = "second"
	// Made before owners were set, as on a cluster that is being upgraded.
	orphan := &triggersv1beta1.TriggerBinding{ObjectMeta: metav1.ObjectMeta{
		Name: "secure-software-supplychain-github-binding-your-app", Namespace: "default",
	}}
	byHand := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "made-by-hand", Namespace: "default"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(first, second, orphan, byHand).Build()
	r := &SupplyChainReconciler{Client: c, Scheme: scheme}

	get := func(obj client.Object, name string) client.Object {
		t.Helper()
		if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, obj); err != nil {
			t.Fatal(err)
		}
		return obj
	}

	// The trigger objects are named for one SupplyChain and controlled by it.
	if err := triggers.EnsureTriggerBinding(ctx, c, scheme, first); err != nil {
		t.Fatal(err)
	}
	if err := triggers.EnsureTriggerTemplate(ctx, c, scheme, first); err != nil {
		t.Fatal(err)
	}
	for name, obj := range map[string]client.Object{
		"secure-software-supplychain-github-binding-your-app":      &triggersv1beta1.TriggerBinding{},
		"secure-software-supplychain-imagebuild-template-your-app": &triggersv1beta1.TriggerTemplate{},
	} {
		ref := ownerRef(get(obj, name), first.UID)
		if ref == nil || ref.Controller == nil || !*ref.Controller {
			t.Errorf("%s is not controlled by its SupplyChain: %v", name, obj.GetOwnerReferences())
		}
	}

	// The ServiceAccount and the Tasks are shared: each SupplyChain that uses
	// them is an owner, and none of them the controller.
	for _, sc := range []*supplychainv1alpha1.SupplyChain{first, second, first} {
		if err := r.ensureServiceAccount(ctx, sc, "supply-chain-runner"); err != nil {
			t.Fatal(err)
		}
		if err := r.reconcileTasks(ctx, sc); err != nil {
			t.Fatal(err)
		}
	}
	tasks := customTasks("default")
	shared := make([]client.Object, 0, len(tasks)+1)
	shared = append(shared, get(&corev1.ServiceAccount{}, "supply-chain-runner"))
	for _, task := range tasks {
		shared = append(shared, get(&tektonv1.Task{}, task.Name))
	}
	for _, obj := range shared {
		if len(obj.GetOwnerReferences()) != 2 || ownerRef(obj, first.UID) == nil || ownerRef(obj, second.UID) == nil {
			t.Errorf("%s is owned by %v, want both SupplyChains once each", obj.GetName(), obj.GetOwnerReferences())
		}
		for _, ref := range obj.GetOwnerReferences() {
			if ref.Controller != nil && *ref.Controller {
				t.Errorf("%s has a controlling owner; it would go with the first SupplyChain deleted", obj.GetName())
			}
		}
	}

	// A ServiceAccount somebody else made is used, and is not ours to remove.
	if err := r.ensureServiceAccount(ctx, first, "made-by-hand"); err != nil {
		t.Fatal(err)
	}
	if refs := get(&corev1.ServiceAccount{}, "made-by-hand").GetOwnerReferences(); len(refs) != 0 {
		t.Errorf("a ServiceAccount made by hand was given owners: %v", refs)
	}
}

// The policy's ServiceAccount is removed with the last policy that uses it.
func TestSupplyChainPolicyOwnsItsServiceAccount(t *testing.T) {
	ctx := context.Background()
	scheme := ownershipScheme(t)
	policyFor := func(name string) *supplychainv1alpha1.SupplyChainPolicy {
		return &supplychainv1alpha1.SupplyChainPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID(name)},
			Spec:       supplychainv1alpha1.SupplyChainPolicySpec{ServiceAccountName: "supply-chain-policy-runner"},
		}
	}
	first, second := policyFor("your-app"), policyFor("your-other-app")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(first, second).Build()
	r := &SupplyChainPolicyReconciler{Client: c, Scheme: scheme}

	for _, scp := range []*supplychainv1alpha1.SupplyChainPolicy{first, second, first} {
		if err := r.ensureServiceAccount(ctx, scp); err != nil {
			t.Fatal(err)
		}
	}
	var sa corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "supply-chain-policy-runner"}, &sa); err != nil {
		t.Fatal(err)
	}
	if len(sa.OwnerReferences) != 2 || ownerRef(&sa, first.UID) == nil || ownerRef(&sa, second.UID) == nil {
		t.Errorf("the ServiceAccount is owned by %v, want both policies once each", sa.OwnerReferences)
	}
}
