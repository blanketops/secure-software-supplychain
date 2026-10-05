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

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// ProviderKubernetes signs with a projected ServiceAccount token.
	ProviderKubernetes = "kubernetes"
	// ProviderSPIFFE signs with a JWT-SVID from the SPIFFE Workload API.
	ProviderSPIFFE = "spiffe"

	// Tekton Chains' configuration is the centre of the signing configuration:
	// the installer writes it, Chains signs provenance from it, and the
	// operator reads the same values so that the pipeline's own signatures and
	// the admission policy cannot disagree with it.
	ChainsConfigNamespace = "tekton-chains"
	ChainsConfigName      = "chains-config"
	ChainsFulcioProvider  = "signers.x509.fulcio.provider"
	ChainsFulcioIssuer    = "signers.x509.fulcio.issuer"
	// ChainsServiceAccount is the ServiceAccount Chains' controller runs as,
	// and therefore the identity it signs with.
	ChainsServiceAccount = "tekton-chains-controller"

	// Tekton's SPIRE configuration holds the trust domain.
	SpireConfigNamespace   = "tekton-pipelines"
	SpireConfigName        = "config-spire"
	SpireConfigTrustDomain = "spire-trust-domain"

	// SPIFFE Workload API, as the SPIFFE CSI driver exposes it in a pod.
	SPIFFECSIDriver  = "csi.spiffe.io"
	SPIFFESocketDir  = "/spiffe-workload-api"
	SPIFFESocketPath = SPIFFESocketDir + "/spire-agent.sock"
	SPIFFESocketEnv  = "SPIFFE_ENDPOINT_SOCKET"
	// cosign, and Chains through cosign's providers, read this variable as a
	// file path: they stat it to decide whether SPIFFE is available and add
	// the unix:// scheme themselves. With the scheme in the value the file is
	// never found and cosign falls back to an interactive login.
	SPIFFESocketValue = SPIFFESocketPath
)

// Identity says how workloads in this cluster identify themselves to Fulcio,
// and therefore what name appears in the certificates their signatures carry.
type Identity struct {
	// Provider is ProviderKubernetes or ProviderSPIFFE.
	Provider string
	// Issuer is the OIDC issuer Fulcio verifies the workload's token against.
	Issuer string
	// TrustDomain is the SPIFFE trust domain. Empty for ProviderKubernetes.
	TrustDomain string
}

// KubernetesIdentity is the identity used when nothing says otherwise.
func KubernetesIdentity() Identity {
	return Identity{Provider: ProviderKubernetes, Issuer: KubernetesOIDCIssuer}
}

// IsSPIFFE reports whether workloads sign with SPIFFE identities.
func (i Identity) IsSPIFFE() bool { return i.Provider == ProviderSPIFFE }

// Subject is the certificate subject of a ServiceAccount under this identity.
func (i Identity) Subject(namespace, serviceAccount string) string {
	if i.IsSPIFFE() {
		return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", i.TrustDomain, namespace, serviceAccount)
	}
	return ServiceAccountIdentity(namespace, serviceAccount)
}

// ChainsSubject is the certificate subject Tekton Chains signs with.
func (i Identity) ChainsSubject() string {
	return i.Subject(ChainsConfigNamespace, ChainsServiceAccount)
}

// IdentityFromConfig derives the identity from the data of Chains' config and
// Tekton's SPIRE config. Anything short of a complete SPIFFE configuration is
// the Kubernetes identity: signing under a half-configured one would produce
// signatures no policy expects.
func IdentityFromConfig(chains, spire map[string]string) (Identity, error) {
	if chains[ChainsFulcioProvider] != ProviderSPIFFE {
		return KubernetesIdentity(), nil
	}
	identity := Identity{
		Provider:    ProviderSPIFFE,
		Issuer:      chains[ChainsFulcioIssuer],
		TrustDomain: spire[SpireConfigTrustDomain],
	}
	if identity.Issuer == "" {
		return Identity{}, fmt.Errorf("%s/%s selects the spiffe provider but sets no %s",
			ChainsConfigNamespace, ChainsConfigName, ChainsFulcioIssuer)
	}
	if identity.TrustDomain == "" {
		return Identity{}, fmt.Errorf("%s/%s selects the spiffe provider but %s/%s sets no %s",
			ChainsConfigNamespace, ChainsConfigName, SpireConfigNamespace, SpireConfigName, SpireConfigTrustDomain)
	}
	return identity, nil
}

// LoadIdentity reads the identity from the cluster. A cluster without Chains'
// config, or without Tekton's SPIRE config, uses the Kubernetes identity.
func LoadIdentity(ctx context.Context, c client.Reader) (Identity, error) {
	data := func(namespace, name string) (map[string]string, error) {
		var cm corev1.ConfigMap
		err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &cm)
		if client.IgnoreNotFound(err) != nil {
			return nil, fmt.Errorf("reading ConfigMap %s/%s: %w", namespace, name, err)
		}
		return cm.Data, nil
	}
	chains, err := data(ChainsConfigNamespace, ChainsConfigName)
	if err != nil {
		return Identity{}, err
	}
	spire, err := data(SpireConfigNamespace, SpireConfigName)
	if err != nil {
		return Identity{}, err
	}
	return IdentityFromConfig(chains, spire)
}
