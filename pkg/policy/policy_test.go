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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

func rootCert(t *testing.T, subject pkix.Name) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func fixtures(t *testing.T) (*supplyv1alpha1.SupplyChainPolicy, *supplyv1alpha1.SupplyChain, map[string]string) {
	t.Helper()
	scp := &supplyv1alpha1.SupplyChainPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
		Spec:       supplyv1alpha1.SupplyChainPolicySpec{SupplyChainRef: supplyv1alpha1.LocalObjectRef{Name: "app"}},
	}
	sc := &supplyv1alpha1.SupplyChain{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
		Spec: supplyv1alpha1.SupplyChainSpec{
			Image:              supplyv1alpha1.ImageSpec{Registry: "docker.io", Name: "org/app"},
			ServiceAccountName: "supply-chain-runner",
			Signing: &supplyv1alpha1.SigningSpec{
				FulcioURL: "http://fulcio.local",
				RekorURL:  "http://rekor.local",
				CTLogURL:  "http://ctlog.local/fulcio",
			},
		},
	}
	roots := map[string]string{
		signing.RootsFulcioKey: rootCert(t, pkix.Name{Organization: []string{"blanketops.dev"}, CommonName: "fulcio"}),
		signing.RootsRekorKey:  "rekor-key",
		signing.RootsCTLogKey:  "ctlog-key",
	}
	return scp, sc, roots
}

func TestRender(t *testing.T) {
	scp, sc, roots := fixtures(t)

	got, err := Render(scp, sc, roots)
	if err != nil {
		t.Fatal(err)
	}

	const name = "team-a-app"
	if len(got.ClusterImagePolicies) != 2 {
		t.Fatalf("got %d ClusterImagePolicies, want signature and authorization", len(got.ClusterImagePolicies))
	}
	signature, authorization := got.ClusterImagePolicies[0], got.ClusterImagePolicies[1]
	wantNames := map[*unstructured.Unstructured]string{
		got.TrustRoot: name,
		signature:     name,
		authorization: name + "-authorization",
	}
	for obj, want := range wantNames {
		if obj.GetName() != want {
			t.Errorf("%s name = %q, want %q", obj.GetKind(), obj.GetName(), want)
		}
		if !OwnedBy(obj, scp) {
			t.Errorf("%s is not labelled as owned by the SupplyChainPolicy", obj.GetKind())
		}
	}

	keys := got.TrustRoot.Object["spec"].(map[string]any)["sigstoreKeys"].(map[string]any)
	ca := keys["certificateAuthorities"].([]any)[0].(map[string]any)
	if ca["uri"] != "http://fulcio.local" {
		t.Errorf("certificate authority uri = %v", ca["uri"])
	}
	subject := ca["subject"].(map[string]any)
	if subject["organization"] != "blanketops.dev" || subject["commonName"] != "fulcio" {
		t.Errorf("certificate authority subject = %v", subject)
	}
	chain, err := base64.StdEncoding.DecodeString(ca["certChain"].(string))
	if err != nil || string(chain) != roots[signing.RootsFulcioKey] {
		t.Errorf("certChain does not round-trip to the Fulcio root (err=%v)", err)
	}
	for field, want := range map[string][2]string{
		"tLogs":  {"http://rekor.local", "rekor-key"},
		"ctLogs": {"http://ctlog.local/fulcio", "ctlog-key"},
	} {
		log := keys[field].([]any)[0].(map[string]any)
		key, _ := base64.StdEncoding.DecodeString(log["publicKey"].(string))
		if log["baseURL"] != want[0] || string(key) != want[1] {
			t.Errorf("%s = %v, want baseURL %q and key %q", field, log, want[0], want[1])
		}
	}

	spec := signature.Object["spec"].(map[string]any)
	if spec["mode"] != "enforce" {
		t.Errorf("mode = %v, want enforce by default", spec["mode"])
	}
	if glob := spec["images"].([]any)[0].(map[string]any)["glob"]; glob != "index.docker.io/org/app**" {
		t.Errorf("glob = %v", glob)
	}
	authority := spec["authorities"].([]any)[0].(map[string]any)
	keyless := authority["keyless"].(map[string]any)
	ctlog := authority["ctlog"].(map[string]any)
	if keyless["trustRootRef"] != name || ctlog["trustRootRef"] != name {
		t.Errorf("authority does not reference TrustRoot %q: %v", name, authority)
	}
	if _, inline := keyless["ca-cert"]; inline {
		t.Error("keyless authority repeats the CA cert instead of using the TrustRoot")
	}
	identity := keyless["identities"].([]any)[0].(map[string]any)
	wantSubject := "https://kubernetes.io/namespaces/team-a/serviceaccounts/supply-chain-runner"
	if identity["issuer"] != signing.KubernetesOIDCIssuer || identity["subject"] != wantSubject {
		t.Errorf("identity = %v", identity)
	}
	wantSigners := []supplyv1alpha1.SignerIdentity{{Issuer: signing.KubernetesOIDCIssuer, Subject: wantSubject}}
	if !reflect.DeepEqual(got.Signers, wantSigners) {
		t.Errorf("Signers = %v, want %v", got.Signers, wantSigners)
	}
	if got.Endpoints.RekorURL != "http://rekor.local" {
		t.Errorf("Endpoints.RekorURL = %q", got.Endpoints.RekorURL)
	}
	if _, has := authority["attestations"]; has {
		t.Error("signature policy also asks for attestations, so a bare signature would not be checked")
	}

	// The authorization policy trusts the same signer and adds the attestation.
	authSpec := authorization.Object["spec"].(map[string]any)
	authAuthority := authSpec["authorities"].([]any)[0].(map[string]any)
	authIdentity := authAuthority["keyless"].(map[string]any)["identities"].([]any)[0].(map[string]any)
	if authIdentity["subject"] != wantSubject || authAuthority["ctlog"].(map[string]any)["trustRootRef"] != name {
		t.Errorf("authorization authority does not match the signer: %v", authAuthority)
	}
	attestation := authAuthority["attestations"].([]any)[0].(map[string]any)
	if attestation["predicateType"] != signing.AuthorizationPredicateType {
		t.Errorf("predicateType = %v", attestation["predicateType"])
	}
	cue := attestation["policy"].(map[string]any)["data"].(string)
	const principal = "system:serviceaccount:team-a:supply-chain-runner"
	for _, want := range []string{
		`predicateType: "` + signing.AuthorizationPredicateType + `"`,
		`scope: {principal: "` + principal + `", resource: "supplychains", verb: "get", allowed: true}`,
		`intent: {principal: "` + principal + `", resource: "imagebuilds", verb: "create", allowed: true}`,
		`output: {principal: "` + principal + `", resource: "imagesignatures", verb: "create", allowed: true}`,
	} {
		if !strings.Contains(cue, want) {
			t.Errorf("authorization policy is missing %q:\n%s", want, cue)
		}
	}
}

func TestRenderSignersAndRekor(t *testing.T) {
	scp, sc, roots := fixtures(t)
	scp.Spec.Signers = []supplyv1alpha1.PolicySigner{
		{ServiceAccountName: "release-signer"},
		{Subject: "https://github.com/blanketops/app/.github/workflows/release.yml@refs/heads/main",
			Issuer: "https://token.actions.githubusercontent.com"},
	}
	scp.Spec.Rekor = &supplyv1alpha1.PolicyRekor{URL: "http://rekor.pinned"}

	got, err := Render(scp, sc, roots)
	if err != nil {
		t.Fatal(err)
	}

	want := []supplyv1alpha1.SignerIdentity{
		{Issuer: signing.KubernetesOIDCIssuer,
			Subject: "https://kubernetes.io/namespaces/team-a/serviceaccounts/release-signer"},
		{Issuer: "https://token.actions.githubusercontent.com",
			Subject: "https://github.com/blanketops/app/.github/workflows/release.yml@refs/heads/main"},
	}
	if !reflect.DeepEqual(got.Signers, want) {
		t.Errorf("Signers = %v, want %v", got.Signers, want)
	}

	// Both policies must trust exactly the stated signers and the pinned log.
	for _, p := range got.ClusterImagePolicies {
		authority := p.Object["spec"].(map[string]any)["authorities"].([]any)[0].(map[string]any)
		identities := authority["keyless"].(map[string]any)["identities"].([]any)
		if len(identities) != len(want) {
			t.Fatalf("%s has %d identities, want %d", p.GetName(), len(identities), len(want))
		}
		for i, identity := range identities {
			got := identity.(map[string]any)
			if got["issuer"] != want[i].Issuer || got["subject"] != want[i].Subject {
				t.Errorf("%s identity %d = %v, want %v", p.GetName(), i, got, want[i])
			}
		}
		if url := authority["ctlog"].(map[string]any)["url"]; url != "http://rekor.pinned" {
			t.Errorf("%s verifies against Rekor %v, want the pinned log", p.GetName(), url)
		}
	}
	keys := got.TrustRoot.Object["spec"].(map[string]any)["sigstoreKeys"].(map[string]any)
	if baseURL := keys["tLogs"].([]any)[0].(map[string]any)["baseURL"]; baseURL != "http://rekor.pinned" {
		t.Errorf("TrustRoot tLog baseURL = %v, want the pinned log", baseURL)
	}
}

func TestRenderMode(t *testing.T) {
	scp, sc, roots := fixtures(t)
	scp.Spec.Mode = "warn"

	got, err := Render(scp, sc, roots)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got.ClusterImagePolicies {
		if mode := p.Object["spec"].(map[string]any)["mode"]; mode != "warn" {
			t.Errorf("%s mode = %v, want warn", p.GetName(), mode)
		}
	}
}

func TestRenderRejectsBadTrustAnchors(t *testing.T) {
	tests := map[string]struct {
		mutate  func(roots map[string]string)
		wantErr string
	}{
		"missing rekor key": {
			mutate:  func(roots map[string]string) { delete(roots, signing.RootsRekorKey) },
			wantErr: signing.RootsRekorKey,
		},
		"blank ctlog key": {
			mutate:  func(roots map[string]string) { roots[signing.RootsCTLogKey] = " \n" },
			wantErr: signing.RootsCTLogKey,
		},
		"fulcio root is not a certificate": {
			mutate:  func(roots map[string]string) { roots[signing.RootsFulcioKey] = "not pem" },
			wantErr: "no PEM certificate",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			scp, sc, roots := fixtures(t)
			tt.mutate(roots)
			_, err := Render(scp, sc, roots)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestCertSubjectFallback(t *testing.T) {
	subject, err := certSubject(rootCert(t, pkix.Name{CommonName: "fulcio"}))
	if err != nil {
		t.Fatal(err)
	}
	if subject["organization"] != "fulcio" || subject["commonName"] != "fulcio" {
		t.Errorf("subject = %v, want the common name used for both", subject)
	}
}

func TestImageGlob(t *testing.T) {
	sc := &supplyv1alpha1.SupplyChain{Spec: supplyv1alpha1.SupplyChainSpec{
		Image: supplyv1alpha1.ImageSpec{Registry: "ghcr.io", Name: "org/app"},
	}}
	if got := ImageGlob(sc); got != "ghcr.io/org/app**" {
		t.Errorf("ImageGlob = %q", got)
	}
}
