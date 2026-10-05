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
package signing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/authz"
)

// AuthorizationPredicateType identifies the in-toto attestation that carries
// the three authorization proofs of a build.
const AuthorizationPredicateType = "https://blanketops.dev/attestations/authorization/v1"

// AuthorizationCheck is one SubjectAccessReview the signing ServiceAccount
// must pass before a build is signed.
type AuthorizationCheck struct {
	Resource string
	Verb     string
}

// The three checks behind ScopeProof, IntentProof and OutputProof.
var (
	ScopeCheck  = AuthorizationCheck{Resource: "supplychains", Verb: "get"}
	IntentCheck = AuthorizationCheck{Resource: "imagebuilds", Verb: "create"}
	OutputCheck = AuthorizationCheck{Resource: "imagesignatures", Verb: "create"}
)

// AuthorizationPredicate is the predicate attested alongside the image
// signature, so admission can require that the build was authorized and not
// only that it was signed.
type AuthorizationPredicate struct {
	Scope  *authz.AuthzProof `json:"scope"`
	Intent *authz.AuthzProof `json:"intent"`
	Output *authz.AuthzProof `json:"output"`
}

// AuthorizationPredicateJSON renders the proofs of this run as the predicate
// the pipeline attests.
func (c *RunSigningContext) AuthorizationPredicateJSON() (string, error) {
	if c.ScopeProof == nil || c.IntentProof == nil || c.OutputProof == nil {
		return "", fmt.Errorf("signing context is missing an authorization proof")
	}
	data, err := json.Marshal(AuthorizationPredicate{
		Scope:  c.ScopeProof,
		Intent: c.IntentProof,
		Output: c.OutputProof,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorization predicate: %w", err)
	}
	return string(data), nil
}

// AuthorizationPolicyCUE is the policy an authorization attestation must
// satisfy: all three proofs present, for this principal, and allowed. The
// admission policy and the pipeline's own verification step both use it, so
// they cannot disagree about what "authorized" means.
func AuthorizationPolicyCUE(principal string) string {
	proof := func(field string, check AuthorizationCheck) string {
		return fmt.Sprintf("\t%s: {principal: %q, resource: %q, verb: %q, allowed: true}\n",
			field, principal, check.Resource, check.Verb)
	}
	return fmt.Sprintf("predicateType: %q\npredicate: {\n", AuthorizationPredicateType) +
		proof("scope", ScopeCheck) +
		proof("intent", IntentCheck) +
		proof("output", OutputCheck) +
		"}\n"
}

// AuthorizeSigner runs the three checks for a build ServiceAccount. It always
// runs all three, so the returned proofs show everything that is missing; the
// error is non-nil if any was denied or could not be evaluated.
func AuthorizeSigner(
	ctx context.Context,
	c client.Client,
	namespace, serviceAccount string,
) (*AuthorizationPredicate, error) {
	var errs []error
	verify := func(check AuthorizationCheck) *authz.AuthzProof {
		proof, err := authz.VerifyAuthorization(ctx, c, serviceAccount, namespace, check.Resource, check.Verb)
		if err != nil {
			errs = append(errs, err)
		}
		return proof
	}
	proofs := &AuthorizationPredicate{
		Scope:  verify(ScopeCheck),
		Intent: verify(IntentCheck),
		Output: verify(OutputCheck),
	}
	return proofs, errors.Join(errs...)
}
