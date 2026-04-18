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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SigningCert holds the ephemeral cert returned by Fulcio.
// This cert is short-lived (typically 20 minutes) and bound to the
// OIDC identity that requested it — the SA's scoped token.
type SigningCert struct {
	// CertPEM is the signing certificate in PEM format.
	CertPEM []byte

	// ChainPEM is the certificate chain (intermediates + root) in PEM format.
	ChainPEM []byte

	// ExpiresAt is when the cert becomes invalid.
	ExpiresAt time.Time
}

// FulcioAuth handles the Fulcio signing cert request.
type FulcioAuth struct {
	// FulcioURL is the Fulcio server endpoint.
	// In-cluster: http://fulcio-server.fulcio-system.svc.cluster.local
	// Public: https://fulcio.sigstore.dev
	FulcioURL string

	// HTTPClient is the HTTP client to use. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

// fulcioRequest is the JSON body sent to Fulcio's /api/v2/signingCert endpoint.
type fulcioRequest struct {
	PublicKeyRequest publicKeyRequest `json:"publicKeyRequest"`
}

type publicKeyRequest struct {
	PublicKey publicKey `json:"publicKey"`
}

type publicKey struct {
	Algorithm string `json:"algorithm"`
	Content   string `json:"content"`
}

// fulcioResponse is the JSON response from Fulcio.
type fulcioResponse struct {
	SignedCertificateEmbeddedSCT signedCert `json:"signedCertificateEmbeddedSct"`
}

type signedCert struct {
	Chain chainInfo `json:"chain"`
}

type chainInfo struct {
	Certificates []string `json:"certificates"`
}

// RequestSigningCert exchanges a scoped OIDC token for a short-lived Fulcio cert.
// The ephemeral ECDSA P-256 keypair is generated per-call — nothing is stored.
//
// Flow:
//  1. Generate ephemeral ECDSA keypair — lives only for this ImageBuildRun
//  2. Marshal the public key as DER, base64-encode it
//  3. POST to Fulcio /api/v2/signingCert with the OIDC token as Bearer auth
//  4. Fulcio validates the token against the cluster's OIDC issuer
//  5. Fulcio binds the SA identity to a short-lived cert
//  6. Return the cert, chain, and the ephemeral private key
func (f *FulcioAuth) RequestSigningCert(ctx context.Context, oidcToken string) (*SigningCert, *ecdsa.PrivateKey, error) {
	// 1. Generate ephemeral ECDSA keypair.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// 2. Marshal public key to DER, then base64-encode.
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pubDER)

	// 3. Build the request body.
	reqBody := fulcioRequest{
		PublicKeyRequest: publicKeyRequest{
			PublicKey: publicKey{
				Algorithm: "ECDSA",
				Content:   pubB64,
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal fulcio request: %w", err)
	}

	// 4. POST to Fulcio.
	url := fmt.Sprintf("%s/api/v2/signingCert", f.FulcioURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create fulcio request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", oidcToken))
	req.Header.Set("Accept", "application/json")

	client := f.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fulcio request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read fulcio response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fulcio returned %d: %s", resp.StatusCode, string(respBody))
	}

	// 5. Parse the response.
	var fulcioResp fulcioResponse
	if err := json.Unmarshal(respBody, &fulcioResp); err != nil {
		return nil, nil, fmt.Errorf("failed to parse fulcio response: %w", err)
	}

	certs := fulcioResp.SignedCertificateEmbeddedSCT.Chain.Certificates
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("fulcio returned no certificates")
	}

	// First cert is the leaf (signing cert), rest are the chain.
	certPEM := []byte(certs[0])
	var chainPEM []byte
	for _, c := range certs[1:] {
		chainPEM = append(chainPEM, []byte(c)...)
	}

	// Parse the leaf cert to get expiry.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode signing cert PEM")
	}

	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse signing cert: %w", err)
	}

	return &SigningCert{
		CertPEM:   certPEM,
		ChainPEM:  chainPEM,
		ExpiresAt: leafCert.NotAfter,
	}, privateKey, nil
}
