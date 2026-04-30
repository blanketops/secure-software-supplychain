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
package authz

import (
	"context"
	"fmt"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AuthzProof is the SAR verdict — embedded into the attestation predicate.
// This is the point-in-time authorization proof that says "this principal
// was authorized to perform this action at this moment."
type AuthzProof struct {
	// Principal is the full SA identity (system:serviceaccount:ns:name).
	Principal string `json:"principal"`

	// Resource is the Kubernetes resource being acted on (e.g. "imagebuildruns").
	Resource string `json:"resource"`

	// Verb is the action being authorized (e.g. "create").
	Verb string `json:"verb"`

	// Allowed is the API server's verdict.
	Allowed bool `json:"allowed"`

	// Reason is the API server's explanation for the verdict.
	Reason string `json:"reason,omitempty"`

	// EvaluatedAt is when the SAR was performed — proves authorization
	// was checked at execution time, not just at deploy time.
	EvaluatedAt time.Time `json:"evaluatedAt"`
}

// VerifyAuthorization performs a SubjectAccessReview for the given principal
// before any signing or pipeline work begins.
//
// The SAR is created as a cluster-scoped resource — the API server evaluates
// it and returns allowed/denied. If denied, the pipeline must not proceed.
//
// This is distinct from the service account's RBAC bindings — the SA might
// have broad permissions, but the SAR proves that *this specific action*
// was authorized *at this specific moment*.
func VerifyAuthorization(
	ctx context.Context,
	c client.Client,
	serviceAccount string,
	namespace string,
	resource string,
	verb string,
) (*AuthzProof, error) {
	sar := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			User: fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount),
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Group:     "supplychain.blanketops.dev",
				Resource:  resource,
			},
		},
	}

	if err := c.Create(ctx, sar); err != nil {
		return nil, fmt.Errorf("SubjectAccessReview request failed: %w", err)
	}

	proof := &AuthzProof{
		Principal:   sar.Spec.User,
		Resource:    resource,
		Verb:        verb,
		Allowed:     sar.Status.Allowed,
		Reason:      sar.Status.Reason,
		EvaluatedAt: time.Now().UTC(),
	}

	if !proof.Allowed {
		return proof, fmt.Errorf(
			"authorization denied for %s to %s %s: %s",
			proof.Principal, verb, resource, proof.Reason,
		)
	}

	return proof, nil
}
