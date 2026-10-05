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
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

const (
	// RootsConfigMap holds the sigstore trust anchors. Created by the installer
	// in every namespace that signs or verifies.
	RootsConfigMap = "blanketops-sigstore-roots"

	// Keys of RootsConfigMap.
	RootsFulcioKey = "fulcio-root.pem"
	RootsRekorKey  = "rekor.pub"
	RootsCTLogKey  = "ctfe.pub"

	// KubernetesOIDCIssuer is the issuer of the ServiceAccount tokens exchanged
	// with Fulcio for signing certs.
	KubernetesOIDCIssuer = "https://kubernetes.default.svc.cluster.local"

	defaultFulcioURL = "https://fulcio.sigstore.dev"
	defaultRekorURL  = "https://rekor.sigstore.dev"
	defaultCTLogURL  = "https://ctfe.sigstore.dev"
)

// Endpoints are the sigstore services a SupplyChain signs against.
type Endpoints struct {
	FulcioURL string
	RekorURL  string
	CTLogURL  string
}

// EndpointsFor resolves the sigstore endpoints of a SupplyChain, falling back
// to the public good instance for anything left unset.
func EndpointsFor(sc *supplyv1alpha1.SupplyChain) Endpoints {
	e := Endpoints{FulcioURL: defaultFulcioURL, RekorURL: defaultRekorURL, CTLogURL: defaultCTLogURL}
	if s := sc.Spec.Signing; s != nil {
		if s.FulcioURL != "" {
			e.FulcioURL = s.FulcioURL
		}
		if s.RekorURL != "" {
			e.RekorURL = s.RekorURL
		}
		if s.CTLogURL != "" {
			e.CTLogURL = s.CTLogURL
		}
	}
	return e
}

// ServiceAccountIdentity is the subject Fulcio puts in a cert issued for a
// Kubernetes ServiceAccount token.
func ServiceAccountIdentity(namespace, serviceAccount string) string {
	return fmt.Sprintf("https://kubernetes.io/namespaces/%s/serviceaccounts/%s", namespace, serviceAccount)
}

// Fingerprint is the SHA-256 of a trust anchor: of the DER bytes when it is
// PEM, so that whitespace and line endings do not change it.
func Fingerprint(pemData string) string {
	data := []byte(strings.TrimSpace(pemData))
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
