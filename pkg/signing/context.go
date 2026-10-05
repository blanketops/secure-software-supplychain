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
	"crypto/ecdsa"
	"fmt"

	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/authz"
)

const (
	sigstoreAudience   = "sigstore"
	tokenExpirySeconds = 600
)

// RunSigningContext is everything downstream needs — the three authorization
// proofs, the ephemeral signing cert, and the private key.
//
// All three proofs go into the attestation predicate that Fulcio signs over.
// The cert + key are used by cosign to sign the image.
// After the pipeline completes, the private key is discarded.
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

	// Cert is the Fulcio-issued ephemeral signing certificate.
	Cert *SigningCert

	// PrivateKey is the ephemeral ECDSA private key that matches the cert.
	// Used for cosign signing, then discarded. Never persisted.
	PrivateKey *ecdsa.PrivateKey

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

// EstablishSigningContext drives the full signing identity flow.
// Five gates, each one feeds the next. If any fails, nothing proceeds.
//
//	SAR scope    → get supplychains       — proves SA can access the chain definition
//	SAR intent   → create imagebuilds    — proves SA is authorized to initiate a build
//	SAR output   → create imagesignatures — proves SA can produce signing records
//	TokenRequest → mints a short-lived OIDC credential for Fulcio
//	Fulcio auth  → exchanges the token for an ephemeral signing cert
//
// All three SARs must pass before the token is minted and Fulcio is called.
// This is what makes the Fulcio cert meaningful — it signs over a complete,
// API-server-verified authorization story at the chain level, not just an identity.
//
// Called by the mediator after prerequisites are ready.
func EstablishSigningContext(
	ctx context.Context,
	c client.Client,
	clientset kubernetes.Interface,
	fulcioURL string,
	serviceAccount string,
	namespace string,
) (*RunSigningContext, error) {
	// -------------------------------------------------------------------------
	// 1. SAR scope — can this SA see the chain definition?
	// -------------------------------------------------------------------------
	scopeProof, err := authz.VerifyAuthorization(
		ctx, c, serviceAccount, namespace, ScopeCheck.Resource, ScopeCheck.Verb,
	)
	if err != nil {
		return nil, fmt.Errorf("scope authorization failed: %w", err)
	}

	// -------------------------------------------------------------------------
	// 2. SAR intent — can this SA initiate a build execution?
	// -------------------------------------------------------------------------
	intentProof, err := authz.VerifyAuthorization(
		ctx, c, serviceAccount, namespace, IntentCheck.Resource, IntentCheck.Verb,
	)
	if err != nil {
		return nil, fmt.Errorf("intent authorization failed: %w", err)
	}

	// -------------------------------------------------------------------------
	// 3. SAR output — can this SA produce signing records?
	// -------------------------------------------------------------------------
	outputProof, err := authz.VerifyAuthorization(
		ctx, c, serviceAccount, namespace, OutputCheck.Resource, OutputCheck.Verb,
	)
	if err != nil {
		return nil, fmt.Errorf("output authorization failed: %w", err)
	}

	// -------------------------------------------------------------------------
	// 4. Scoped token — mint a short-lived OIDC credential.
	//    Only reached if all three SARs passed.
	// -------------------------------------------------------------------------
	token, err := authz.RequestScopedToken(
		ctx, clientset, serviceAccount, namespace,
		sigstoreAudience, tokenExpirySeconds,
	)
	if err != nil {
		return nil, fmt.Errorf("scoped token request failed: %w", err)
	}

	// -------------------------------------------------------------------------
	// 5. Fulcio — exchange the OIDC token for an ephemeral signing cert.
	// -------------------------------------------------------------------------
	fa := &FulcioAuth{FulcioURL: fulcioURL}
	cert, privKey, err := fa.RequestSigningCert(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("fulcio cert request failed: %w", err)
	}

	return &RunSigningContext{
		ScopeProof:  scopeProof,
		IntentProof: intentProof,
		OutputProof: outputProof,
		Cert:        cert,
		PrivateKey:  privKey,
	}, nil
}
