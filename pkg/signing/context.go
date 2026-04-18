/*
Copyright 2026.
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

	"github.com/ntlaletsi70/blanketops-environments-supply-chain/pkg/authz"
)

const (
	sigstoreAudience   = "sigstore"
	tokenExpirySeconds = 600
)

// RunSigningContext is everything downstream needs — the authorization proof,
// the ephemeral signing cert, and the private key.
//
// The proof goes into the attestation predicate.
// The cert + key are used by cosign to sign the image.
// After the pipeline completes, the private key is discarded.
type RunSigningContext struct {
	// Proof is the SAR verdict — proves authorization at execution time.
	Proof *authz.AuthzProof

	// Cert is the Fulcio-issued ephemeral signing certificate.
	Cert *SigningCert

	// PrivateKey is the ephemeral ECDSA private key that matches the cert.
	// Used for cosign signing, then discarded. Never persisted.
	PrivateKey *ecdsa.PrivateKey
}

// EstablishSigningContext drives the full signing identity flow.
// Three gates, each one feeds the next. If any fails, nothing proceeds.
//
//	SAR check      → proves the SA is authorized to run this build right now
//	TokenRequest   → mints a short-lived OIDC credential for Fulcio
//	Fulcio auth    → exchanges the token for an ephemeral signing cert
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
	// 1. SAR — prove authorization.
	// -------------------------------------------------------------------------
	proof, err := authz.VerifyAuthorization(
		ctx, c, serviceAccount, namespace, "imagebuildruns", "create",
	)
	if err != nil {
		return nil, fmt.Errorf("authorization check failed: %w", err)
	}

	// -------------------------------------------------------------------------
	// 2. Scoped token — mint a short-lived OIDC credential.
	// -------------------------------------------------------------------------
	token, err := authz.RequestScopedToken(
		ctx, clientset, serviceAccount, namespace,
		sigstoreAudience, tokenExpirySeconds,
	)
	if err != nil {
		return nil, fmt.Errorf("scoped token request failed: %w", err)
	}

	// -------------------------------------------------------------------------
	// 3. Fulcio — exchange the OIDC token for an ephemeral signing cert.
	// -------------------------------------------------------------------------
	fa := &FulcioAuth{FulcioURL: fulcioURL}
	cert, privKey, err := fa.RequestSigningCert(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("fulcio cert request failed: %w", err)
	}

	return &RunSigningContext{
		Proof:      proof,
		Cert:       cert,
		PrivateKey: privKey,
	}, nil
}
