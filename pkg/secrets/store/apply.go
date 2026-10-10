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

package store

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Outcome says what Apply did.
type Outcome string

const (
	Created   Outcome = "created"
	Updated   Outcome = "updated"
	Unchanged Outcome = "unchanged"
)

// Apply makes an ExternalSecret be what the operator wants it to be: created
// when it is missing, and put back when its spec has been changed.
//
// The operator owns these objects. Which store they read from and which
// secrets and fields they ask for are part of how a build gets its
// credentials, not settings to be adjusted on the object: a store of one's
// own has to serve the same names (see the package comment).
//
// Fields the operator does not set, such as the defaults External Secrets
// adds, are left alone and are not a difference.
func Apply(ctx context.Context, c client.Client, desired *unstructured.Unstructured) (Outcome, error) {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(desired.GroupVersionKind())
	err := c.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if apierrors.IsNotFound(err) {
		return Created, c.Create(ctx, desired)
	}
	if err != nil {
		return "", err
	}
	if equality.Semantic.DeepDerivative(desired.Object["spec"], existing.Object["spec"]) {
		return Unchanged, nil
	}
	existing.Object["spec"] = desired.Object["spec"]
	return Updated, c.Update(ctx, existing)
}
