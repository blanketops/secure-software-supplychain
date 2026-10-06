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
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/authz"
)

// RunSigningContext is what a build carries from the controller into its
// pipeline: the three authorization proofs, and how the pipeline's signing
// steps identify themselves to Fulcio.
//
// It holds no certificate and no key. The steps that sign obtain their own
// from Fulcio, inside the build, with the build's identity; the controller
// never has signing material for an image.
type RunSigningContext struct {
	// ScopeProof — get supplychains
	// "I can see the chain I am claiming to execute against."
	ScopeProof *authz.AuthzProof

	// IntentProof — create imagebuilds
	// "I am authorized to initiate a build execution against this chain."
	IntentProof *authz.AuthzProof

	// OutputProof — create imagesignatures
	// "I am authorized to produce signing records for what I am about to sign."
	OutputProof *authz.AuthzProof

	// Identity is how the pipeline's signing steps identify themselves to
	// Fulcio, taken from the cluster's signing configuration. The zero value
	// means the Kubernetes identity; use SigningIdentity to read it.
	Identity Identity
}

// SigningIdentity is the identity the pipeline signs with.
func (c *RunSigningContext) SigningIdentity() Identity {
	if c == nil || c.Identity.Provider == "" {
		return KubernetesIdentity()
	}
	return c.Identity
}

// EstablishSigningContext reviews the build ServiceAccount before a build
// starts. All three checks must pass or nothing proceeds:
//
//	scope  → get supplychains       — it can read the chain it builds for
//	intent → create imagebuilds     — it may start a build
//	output → create imagesignatures — it may record what it signs
//
// The proofs are attested to the image by the pipeline, so admission can
// require that the build was authorized and not only that it was signed.
func EstablishSigningContext(
	ctx context.Context,
	c client.Client,
	serviceAccount string,
	namespace string,
) (*RunSigningContext, error) {
	proofs, err := AuthorizeSigner(ctx, c, namespace, serviceAccount)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}
	return &RunSigningContext{
		ScopeProof:  proofs.Scope,
		IntentProof: proofs.Intent,
		OutputProof: proofs.Output,
	}, nil
}
