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
	"strings"
	"testing"
)

func TestIdentityFromConfig(t *testing.T) {
	const issuer = "http://oidc.spire.svc"
	spiffeChains := map[string]string{ChainsFulcioProvider: ProviderSPIFFE, ChainsFulcioIssuer: issuer}
	spire := map[string]string{SpireConfigTrustDomain: "blanketops.dev"}

	tests := map[string]struct {
		chains, spire map[string]string
		want          Identity
		wantErr       string
	}{
		"no config at all": {want: KubernetesIdentity()},
		"chains without a provider": {
			chains: map[string]string{ChainsFulcioIssuer: KubernetesOIDCIssuer},
			spire:  spire, // a trust domain alone does not switch signing over
			want:   KubernetesIdentity(),
		},
		"spiffe": {
			chains: spiffeChains, spire: spire,
			want: Identity{Provider: ProviderSPIFFE, Issuer: issuer, TrustDomain: "blanketops.dev"},
		},
		"spiffe without a trust domain": {chains: spiffeChains, wantErr: SpireConfigTrustDomain},
		"spiffe without an issuer": {
			chains: map[string]string{ChainsFulcioProvider: ProviderSPIFFE}, spire: spire,
			wantErr: ChainsFulcioIssuer,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := IdentityFromConfig(tt.chains, tt.spire)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("identity = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestIdentitySubject(t *testing.T) {
	if got, want := KubernetesIdentity().Subject("default", "runner"),
		"https://kubernetes.io/namespaces/default/serviceaccounts/runner"; got != want {
		t.Errorf("kubernetes subject = %q, want %q", got, want)
	}
	spiffe := Identity{Provider: ProviderSPIFFE, TrustDomain: "blanketops.dev"}
	if got, want := spiffe.Subject("default", "runner"), "spiffe://blanketops.dev/ns/default/sa/runner"; got != want {
		t.Errorf("spiffe subject = %q, want %q", got, want)
	}
}

func TestWorkloadEntry(t *testing.T) {
	identity := Identity{Provider: ProviderSPIFFE, Issuer: "http://oidc.example", TrustDomain: "example.org"}
	entry := WorkloadEntry(identity, "team-a", "supply-chain-runner")

	if got := entry.GetName(); got != "team-a-supply-chain-runner" {
		t.Errorf("name = %q", got)
	}
	spec := entry.Object["spec"].(map[string]any)
	want := map[string]any{
		"className": "spire-server-spire",
		"spiffeID":  "spiffe://example.org/ns/team-a/sa/supply-chain-runner",
		"parentID":  "spiffe://example.org/supply-chain/nodes",
	}
	for k, v := range want {
		if spec[k] != v {
			t.Errorf("spec.%s = %v, want %v", k, spec[k], v)
		}
	}
	selectors := spec["selectors"].([]any)
	if len(selectors) != 2 || selectors[0] != "k8s:ns:team-a" || selectors[1] != "k8s:sa:supply-chain-runner" {
		t.Errorf("selectors = %v", selectors)
	}
}
