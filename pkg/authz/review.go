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

	// Group is the API group of the resource.
	Group string `json:"group,omitempty"`

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

// Principal is the Kubernetes username of a ServiceAccount, as recorded in
// AuthzProof.Principal.
func Principal(namespace, serviceAccount string) string {
	return fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount)
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
	return Verify(ctx, c, serviceAccount, namespace, Check{Group: SupplyChainGroup, Resource: resource, Verb: verb})
}

// SupplyChainGroup is the API group of this operator's resources.
const SupplyChainGroup = "supplychain.blanketops.dev"

// Check is one action a ServiceAccount must be authorized for.
type Check struct {
	Group    string
	Resource string
	Verb     string
	// ClusterScoped is set for resources that live outside any namespace; the
	// review is then not limited to the ServiceAccount's namespace.
	ClusterScoped bool
}

// Verify performs the SubjectAccessReview for one Check. The returned proof is
// set whenever the API server answered, including when it answered "denied",
// in which case the error says so.
func Verify(
	ctx context.Context,
	c client.Client,
	serviceAccount string,
	namespace string,
	check Check,
) (*AuthzProof, error) {
	resource, verb := check.Resource, check.Verb
	reviewNamespace := namespace
	if check.ClusterScoped {
		reviewNamespace = ""
	}
	sar := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			User: Principal(namespace, serviceAccount),
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: reviewNamespace,
				Verb:      verb,
				Group:     check.Group,
				Resource:  resource,
			},
		},
	}

	if err := c.Create(ctx, sar); err != nil {
		return nil, fmt.Errorf("SubjectAccessReview request failed: %w", err)
	}

	proof := &AuthzProof{
		Principal:   sar.Spec.User,
		Group:       check.Group,
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
