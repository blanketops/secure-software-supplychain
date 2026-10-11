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
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Where the keys are kept is the user's to choose, between the two places
// they can be, and Vault means the Vault this installer runs.
func TestKeyResidency(t *testing.T) {
	options := Options{}
	if err := options.defaultAndValidate(); err != nil || options.KeyResidency != ResidencyCluster {
		t.Errorf("the default is %q, %v; want %q", options.KeyResidency, err, ResidencyCluster)
	}
	for _, bad := range []Options{
		{KeyResidency: "hsm"},
		{KeyResidency: ResidencyVault, VaultAddr: "https://vault.example:8200"},
		{KeyResidency: ResidencyVault, ExternalSecretStore: true},
	} {
		if err := bad.defaultAndValidate(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}

	names := func(o Options) string {
		i := &Installer{opts: o}
		steps, _ := i.stepsToRun()
		var out []string
		for _, s := range steps {
			out = append(out, s.Name)
		}
		return strings.Join(out, ",")
	}
	// The keys are made after Vault is up and before either service starts.
	if got := names(Options{KeyResidency: ResidencyVault}); !strings.Contains(got, "Vault,Signing Keys,Fulcio,Rekor") {
		t.Errorf("with keys in Vault the order is %s", got)
	}
	if got := names(Options{KeyResidency: ResidencyCluster}); strings.Contains(got, "Signing Keys") {
		t.Errorf("with keys in the cluster there is a Signing Keys step: %s", got)
	}
}

// The keys are made in Vault once and are never replaced: everything signed
// with them would stop verifying. They cannot be exported, and each service
// may sign with its own and do nothing else.
func TestSigningKeysInVault(t *testing.T) {
	fake := newFakeVault()
	vault := clientFor(t, fake)
	ctx := context.Background()

	for range 2 {
		if err := ensureTransitEngine(ctx, vault); err != nil {
			t.Fatal(err)
		}
		for _, svc := range signingServices {
			if err := ensureTransitKey(ctx, vault, svc.Key); err != nil {
				t.Fatal(err)
			}
		}
	}
	if engine, _ := fake.mounts[transitMount+"/"].(map[string]any); engine["type"] != "transit" || fake.enabled != 1 {
		t.Errorf("the transit engine: %v, enabled %d times", engine, fake.enabled)
	}
	if !reflect.DeepEqual(fake.created, []string{fulcioKey, rekorKey}) {
		t.Errorf("keys created: %v; want each of the two once", fake.created)
	}
	for name, request := range fake.keyRequests {
		if request["exportable"] != false || request["allow_plaintext_backup"] != false || request["type"] != "ecdsa-p256" {
			t.Errorf("key %s was created with %v", name, request)
		}
	}

	policy := signerPolicy(rekorKey)
	for _, want := range []string{
		`path "transit/sign/rekor"`, `path "transit/verify/rekor"`, `path "transit/keys/rekor"`,
		// Sigstore's client signs at transit/sign/<key>/<hash algorithm>.
		`path "transit/sign/rekor/*"`, `path "transit/verify/rekor/*"`,
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the policy does not allow %s", want)
		}
	}
	if strings.Count(policy, "*") != 2 || strings.Contains(policy, `keys/rekor/*`) || strings.Contains(policy, `"transit/*`) {
		t.Errorf("the policy is wider than one key's sign and verify:\n%s", policy)
	}
	for _, never := range []string{"export", "rotate", "delete", "create", fulcioKey, "secret/"} {
		if strings.Contains(policy, never) {
			t.Errorf("Rekor's policy mentions %q:\n%s", never, policy)
		}
	}

	// A mount of that name that is something else is not taken over.
	other := newFakeVault()
	other.mounts[transitMount+"/"] = map[string]any{"type": "kv"}
	if err := ensureTransitEngine(ctx, clientFor(t, other)); err == nil {
		t.Error("a mount that is not the transit engine was accepted")
	}
}

// Fulcio's root certificate is issued for a key the installer never sees:
// Vault signs it. It has to be a CA certificate that verifies with the key
// Vault holds, and one that is already there for that key is the trust
// anchor and is kept.
func TestFulcioRootIsIssuedByTheKeyInVault(t *testing.T) {
	fake := newFakeVault()
	vault := clientFor(t, fake)
	ctx := context.Background()
	if err := ensureTransitKey(ctx, vault, fulcioKey); err != nil {
		t.Fatal(err)
	}
	signer, err := newTransitSigner(ctx, vault, fulcioKey)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(&fake.transit[fulcioKey].PublicKey) {
		t.Fatal("the signer's public key is not the one in Vault")
	}

	rootPEM, err := fulcioRootCertificate(signer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 || !root.BasicConstraintsValid {
		t.Errorf("the root cannot issue certificates: CA=%v usage=%v", root.IsCA, root.KeyUsage)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Errorf("the root does not verify with the key in Vault: %v", err)
	}
	// Fulcio checks that its chain can issue code-signing certificates.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := root.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		t.Errorf("the root is not valid for code signing: %v", err)
	}

	if !certifies(rootPEM, signer.Public()) {
		t.Error("the root is not recognised as being for the key in Vault")
	}
	if err := ensureTransitKey(ctx, vault, rekorKey); err != nil {
		t.Fatal(err)
	}
	another, _ := newTransitSigner(ctx, vault, rekorKey)
	if certifies(rootPEM, another.Public()) || certifies([]byte("not a certificate"), signer.Public()) {
		t.Error("a certificate for another key, or none, is taken for the root")
	}

	// The signer signs what X.509 asks of it and nothing else.
	digest := sha256.Sum256([]byte("statement"))
	if _, err := signer.Sign(nil, digest[:], crypto.SHA512); err == nil {
		t.Error("a digest of another algorithm was signed")
	}
}

// With the keys in Vault, neither service is given a key file: the Job that
// makes Fulcio's is left out, the Secrets that held them are not mounted, and
// each pod gets an agent that logs it in and holds its token.
func TestKeysInVaultMutation(t *testing.T) {
	deployment := func(file, name string) (*unstructured.Unstructured, map[string]any, []string) {
		obj := find(t, manifestObjects(t, file), "Deployment", name)
		if !keysInVaultMutation(obj) {
			t.Fatalf("%s is left out", name)
		}
		spec, _, _ := unstructured.NestedMap(obj.Object, "spec", "template", "spec")
		var server map[string]any
		var containers []string
		for _, c := range spec["containers"].([]any) {
			container := c.(map[string]any)
			containers = append(containers, container["name"].(string))
			if container["name"] == name {
				server = container
			}
		}
		return obj, server, containers
	}
	named := func(list any) []string {
		var out []string
		for _, item := range list.([]any) {
			out = append(out, item.(map[string]any)["name"].(string))
		}
		return out
	}
	text := func(v any) string { return strings.Join(stringsOf(v), " ") }

	fulcio, server, containers := deployment("dependencies/sigstore/fulcio/release.yaml", "fulcio-server")
	args := text(server["args"])
	for _, want := range []string{
		"--ca=kmsca", "--kms-resource=hashivault://fulcio-ca", "--kms-cert-chain-path=/etc/fulcio-kms/cert",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("fulcio is not started with %s: %s", want, args)
		}
	}
	if strings.Contains(args, "fileca") || strings.Contains(args, "PASSWORD") || strings.Contains(args, "fulcio-secrets") {
		t.Errorf("fulcio is still pointed at a key file: %s", args)
	}
	// What was there for other reasons stays.
	for _, kept := range []string{"--host=127.0.0.1", "--ct-log-url=" + ctLogURL, "--config-path="} {
		if !strings.Contains(args, kept) {
			t.Errorf("fulcio lost %s", kept)
		}
	}
	volumes, _, _ := unstructured.NestedSlice(fulcio.Object, "spec", "template", "spec", "volumes")
	if got := strings.Join(named(volumes), ","); strings.Contains(got, "fulcio-cert") ||
		!strings.Contains(got, "fulcio-root") || !strings.Contains(got, "vault-agent") {
		t.Errorf("fulcio's volumes: %s", got)
	}
	if got := strings.Join(named(server["env"]), ","); strings.Contains(got, "PASSWORD") ||
		!strings.Contains(got, "VAULT_ADDR") || !strings.Contains(got, "SSL_CERT_DIR") {
		t.Errorf("fulcio's environment: %s", got)
	}
	if !reflect.DeepEqual(containers, []string{"fulcio-server", "tls", "vault-agent"}) {
		t.Errorf("fulcio's containers: %v", containers)
	}

	rekor, server, containers := deployment("dependencies/sigstore/rekor/release.yaml", "rekor-server")
	if args := text(server["args"]); !strings.Contains(args, "--rekor_server.signer=hashivault://rekor") ||
		strings.Contains(args, "key.pem") {
		t.Errorf("rekor's signer: %s", args)
	}
	volumes, _, _ = unstructured.NestedSlice(rekor.Object, "spec", "template", "spec", "volumes")
	if got := strings.Join(named(volumes), ","); strings.Contains(got, "signing-key") || !strings.Contains(got, "tls-ca") {
		t.Errorf("rekor's volumes: %s", got)
	}
	if got := strings.Join(named(server["volumeMounts"]), ","); strings.Contains(got, "signing-key") {
		t.Errorf("rekor still mounts %s", got)
	}
	if !reflect.DeepEqual(containers, []string{"rekor-server", "tls", "vault-agent"}) {
		t.Errorf("rekor's containers: %v", containers)
	}

	// Every mount of every container has a volume behind it.
	for _, obj := range []*unstructured.Unstructured{fulcio, rekor} {
		spec, _, _ := unstructured.NestedMap(obj.Object, "spec", "template", "spec")
		have := strings.Join(named(spec["volumes"]), ",") + ","
		for _, c := range spec["containers"].([]any) {
			for _, mount := range named(c.(map[string]any)["volumeMounts"]) {
				if !strings.Contains(have, mount+",") {
					t.Errorf("%s: container %v mounts %s, which is not a volume", obj.GetName(), c.(map[string]any)["name"], mount)
				}
			}
		}
	}

	job := find(t, manifestObjects(t, "dependencies/sigstore/fulcio/release.yaml"), "Job", "fulcio-createcerts")
	if keysInVaultMutation(job) {
		t.Error("the Job that makes a CA key file is still applied")
	}
	// With the keys in the cluster nothing is changed.
	untouched := find(t, manifestObjects(t, "dependencies/sigstore/rekor/release.yaml"), "Deployment", "rekor-server")
	before := untouched.DeepCopy()
	if i := (&Installer{opts: Options{KeyResidency: ResidencyCluster}}); !mutateForKeyResidency(i, untouched) ||
		!reflect.DeepEqual(before.Object, untouched.Object) {
		t.Error("the manifests are changed when the keys stay in the cluster")
	}
}

// The agent logs in as the pod's ServiceAccount for one role, verifies Vault
// against the CA, and listens only inside the pod.
func TestVaultAgentConfig(t *testing.T) {
	config := vaultAgentConfig(rekorSignerRole)
	for _, want := range []string{
		`address = "` + vaultAddress + `"`, `ca_cert = "` + caMountDir + "/" + caKey + `"`,
		`mount_path = "auth/kubernetes"`, `role = "rekor-signer"`,
		`use_auto_auth_token = "force"`, `address     = "127.0.0.1:8100"`,
	} {
		if !strings.Contains(config, want) {
			t.Errorf("the agent's configuration has no %s:\n%s", want, config)
		}
	}
	if strings.Contains(config, "0.0.0.0") {
		t.Error("the agent listens outside the pod")
	}
}
