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

package cli

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
)

func TestNewRekorSigningKey(t *testing.T) {
	keyPEM, err := newRekorSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("not a PKCS#8 PEM block: %v", block)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("key is %T, want *ecdsa.PrivateKey", key)
	}
}

// Rekor with an in-memory signer makes a new key on every restart, which
// silently breaks verification of everything signed before.
func TestRekorSignsWithThePersistentKey(t *testing.T) {
	data, err := manifests.Dependencies.ReadFile("dependencies/sigstore/rekor/release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	release := string(data)
	if strings.Contains(release, `"--rekor_server.signer=memory"`) {
		t.Error("Rekor is configured with an in-memory signing key")
	}
	for _, want := range []string{
		`"--rekor_server.signer=/var/run/rekor-signer/` + rekorSigningKeyFile + `"`,
		"secretName: " + rekorSigningKeySecret,
	} {
		if !strings.Contains(release, want) {
			t.Errorf("Rekor manifest does not contain %q", want)
		}
	}
}
