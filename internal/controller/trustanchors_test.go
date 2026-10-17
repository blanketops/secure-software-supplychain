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
	"errors"
	"maps"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	"github.com/blanketops/secure-software-supplychain/pkg/signing"
)

// A SupplyChain or SupplyChainPolicy can live in any namespace, the
// operator's own included: builds and policies read the trust anchors from
// their namespace, so the operator keeps a copy there of the installer's.
func TestTheTrustAnchorsFollowASupplyChainToItsNamespace(t *testing.T) {
	const ns = "secure-software-supply-chain-system"
	anchors := map[string]string{
		signing.RootsFulcioKey: "fulcio", signing.RootsRekorKey: "rekor", signing.RootsCTLogKey: "ctlog",
	}
	source := func(data map[string]string) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: signing.RootsConfigMap, Namespace: signing.RootsSourceNamespace},
			Data:       maps.Clone(data),
		}
	}
	chain := &supplychainv1alpha1.SupplyChain{ObjectMeta: metav1.ObjectMeta{Name: "your-app", Namespace: ns, UID: "chain"}}
	policy := &supplychainv1alpha1.SupplyChainPolicy{ObjectMeta: metav1.ObjectMeta{Name: "your-app", Namespace: ns, UID: "policy"}}
	copyKey := types.NamespacedName{Namespace: ns, Name: signing.RootsConfigMap}
	ctx := context.Background()
	scheme := ownershipScheme(t)

	t.Run("copied into the namespace, owned by what uses it", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(source(anchors)).Build()
		if err := ensureTrustAnchors(ctx, c, scheme, chain); err != nil {
			t.Fatal(err)
		}
		var got corev1.ConfigMap
		if err := c.Get(ctx, copyKey, &got); err != nil {
			t.Fatalf("no copy in %s: %v", ns, err)
		}
		if !maps.Equal(got.Data, anchors) {
			t.Errorf("data: got %v, want %v", got.Data, anchors)
		}
		if !managed(&got) || ownerRef(&got, chain.UID) == nil {
			t.Errorf("the copy should be managed and owned by the SupplyChain: labels %v, owners %v",
				got.Labels, got.OwnerReferences)
		}

		// The policy in the same namespace shares it; a changed source is followed.
		changed := maps.Clone(anchors)
		changed[signing.RootsRekorKey] = "rekor, rotated"
		var src corev1.ConfigMap
		_ = c.Get(ctx, client.ObjectKeyFromObject(source(nil)), &src)
		src.Data = changed
		if err := c.Update(ctx, &src); err != nil {
			t.Fatal(err)
		}
		if err := ensureTrustAnchors(ctx, c, scheme, policy); err != nil {
			t.Fatal(err)
		}
		if err := ensureTrustAnchors(ctx, c, scheme, chain); err != nil {
			t.Fatal(err)
		}
		_ = c.Get(ctx, copyKey, &got)
		if !maps.Equal(got.Data, changed) {
			t.Errorf("the copy did not follow the source: %v", got.Data)
		}
		if ownerRef(&got, chain.UID) == nil || ownerRef(&got, policy.UID) == nil || len(got.OwnerReferences) != 2 {
			t.Errorf("owners: got %v, want the SupplyChain and the policy once each", got.OwnerReferences)
		}
	})

	t.Run("a ConfigMap the operator did not create is left alone", func(t *testing.T) {
		theirs := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: signing.RootsConfigMap, Namespace: ns},
			Data:       map[string]string{signing.RootsFulcioKey: "their own"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(source(anchors), theirs).Build()
		if err := ensureTrustAnchors(ctx, c, scheme, chain); err != nil {
			t.Fatal(err)
		}
		var got corev1.ConfigMap
		_ = c.Get(ctx, copyKey, &got)
		if got.Data[signing.RootsFulcioKey] != "their own" || len(got.OwnerReferences) != 0 {
			t.Errorf("changed a ConfigMap the operator did not create: %v, owners %v", got.Data, got.OwnerReferences)
		}
	})

	t.Run("nothing to do in the installer's own namespace", func(t *testing.T) {
		inSource := &supplychainv1alpha1.SupplyChain{ObjectMeta: metav1.ObjectMeta{
			Name: "your-app", Namespace: signing.RootsSourceNamespace, UID: "in-source"}}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(source(anchors)).Build()
		if err := ensureTrustAnchors(ctx, c, scheme, inSource); err != nil {
			t.Fatal(err)
		}
		var got corev1.ConfigMap
		_ = c.Get(ctx, client.ObjectKeyFromObject(source(nil)), &got)
		if len(got.OwnerReferences) != 0 || managed(&got) {
			t.Errorf("the installer's ConfigMap was changed: labels %v, owners %v", got.Labels, got.OwnerReferences)
		}
	})

	t.Run("without the installer's, nothing is copied", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		if err := ensureTrustAnchors(ctx, c, scheme, chain); !errors.Is(err, errTrustAnchorsMissing) {
			t.Fatalf("got %v, want errTrustAnchorsMissing", err)
		}
		if err := c.Get(ctx, copyKey, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
			t.Errorf("a ConfigMap was created without a source: %v", err)
		}
	})
}
