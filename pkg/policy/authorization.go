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

package policy

import (
	"context"
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/authz"
)

// DefaultServiceAccount is the ServiceAccount a SupplyChainPolicy is rendered
// on behalf of when it names none.
const DefaultServiceAccount = "supply-chain-policy-runner"

// The three checks the policy's ServiceAccount must pass before a
// SupplyChainPolicy is rendered. They mirror the scope, intent and output
// proofs the signing ServiceAccount gives before a build.
var (
	// ScopeCheck: it can read the SupplyChain it sets policy for.
	ScopeCheck = authz.Check{Group: authz.SupplyChainGroup, Resource: "supplychains", Verb: "get"}
	// IntentCheck: it may declare admission policy for that SupplyChain.
	IntentCheck = authz.Check{Group: authz.SupplyChainGroup, Resource: "supplychainpolicies", Verb: "create"}
	// OutputCheck: it may produce the cluster-wide admission policies.
	OutputCheck = authz.Check{
		Group: ClusterImagePolicyGVK.Group, Resource: "clusterimagepolicies", Verb: "create", ClusterScoped: true,
	}
)

// Authorize runs the three checks for the ServiceAccount of scp. It always
// runs all three, so the returned proofs show everything that is missing; the
// error is non-nil if any was denied or could not be evaluated.
func Authorize(
	ctx context.Context,
	c client.Client,
	scp *supplyv1alpha1.SupplyChainPolicy,
) (*supplyv1alpha1.PolicyAuthorization, error) {
	serviceAccount := scp.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = DefaultServiceAccount
	}

	var errs []error
	verify := func(check authz.Check) *supplyv1alpha1.AuthorizationProof {
		proof, err := authz.Verify(ctx, c, serviceAccount, scp.Namespace, check)
		if err != nil {
			errs = append(errs, err)
		}
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
	authorization := &supplyv1alpha1.PolicyAuthorization{
		Scope:  verify(ScopeCheck),
		Intent: verify(IntentCheck),
		Output: verify(OutputCheck),
	}
	return authorization, errors.Join(errs...)
}
