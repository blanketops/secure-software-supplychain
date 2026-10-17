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
	"maps"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/blanketops/secure-software-supplychain/pkg/signing"
)

// errTrustAnchorsMissing is returned while the installer's trust anchors do
// not exist, before the dependencies are installed.
var errTrustAnchorsMissing = fmt.Errorf("ConfigMap %s/%s not found: install the dependencies first",
	signing.RootsSourceNamespace, signing.RootsConfigMap)

// ensureTrustAnchors makes the sigstore trust anchors available in owner's
// namespace. Builds mount them, and policies render them, from their own
// namespace, while the installer creates them only in
// signing.RootsSourceNamespace and default. Anywhere else the operator keeps
// a copy, shared by every SupplyChain and SupplyChainPolicy that uses it and
// removed with the last of them, and brings it up to date when the
// installer's changes. A ConfigMap of that name the operator did not create,
// such as the installer's own, is left as it is.
func ensureTrustAnchors(ctx context.Context, c client.Client, scheme *runtime.Scheme, owner client.Object) error {
	var source corev1.ConfigMap
	err := c.Get(ctx, types.NamespacedName{Namespace: signing.RootsSourceNamespace, Name: signing.RootsConfigMap}, &source)
	if apierrors.IsNotFound(err) {
		return errTrustAnchorsMissing
	}
	if err != nil {
		return fmt.Errorf("reading the trust anchors: %w", err)
	}
	namespace := owner.GetNamespace()
	if namespace == signing.RootsSourceNamespace {
		return nil
	}

	var copied corev1.ConfigMap
	err = c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: signing.RootsConfigMap}, &copied)
	if apierrors.IsNotFound(err) {
		copied = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      signing.RootsConfigMap,
				Namespace: namespace,
				Labels:    map[string]string{managedLabel: "true"},
			},
			Data: maps.Clone(source.Data),
		}
		if _, err := shareWith(owner, &copied, scheme); err != nil {
			return err
		}
		if err := c.Create(ctx, &copied); err != nil {
			return fmt.Errorf("copying the trust anchors to %s: %w", namespace, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the trust anchors in %s: %w", namespace, err)
	}
	if !managed(&copied) {
		return nil
	}
	changed, err := shareWith(owner, &copied, scheme)
	if err != nil {
		return err
	}
	if !maps.Equal(copied.Data, source.Data) {
		copied.Data = maps.Clone(source.Data)
		changed = true
	}
	if !changed {
		return nil
	}
	if err := c.Update(ctx, &copied); err != nil {
		return fmt.Errorf("updating the trust anchors in %s: %w", namespace, err)
	}
	return nil
}

// isTrustAnchorsSource reports whether obj is the installer's copy of the
// trust anchors, the one every other copy follows.
func isTrustAnchorsSource(obj client.Object) bool {
	return obj.GetNamespace() == signing.RootsSourceNamespace && obj.GetName() == signing.RootsConfigMap
}
