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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"sigs.k8s.io/yaml"

	manifests "github.com/blanketops/secure-software-supplychain"
	"github.com/blanketops/secure-software-supplychain/pkg/secrets/store"
)

// fakeVault keeps what the installer configures and what is written to the
// key-value engine, and counts how often each thing was created.
type fakeVault struct {
	token       string
	mounts      map[string]any
	auths       map[string]any
	configs     map[string]map[string]any
	policies    map[string]string
	roles       map[string]map[string]any
	secrets     map[string]map[string]string
	enabled     int
	transit     map[string]*ecdsa.PrivateKey
	audit       map[string]any
	created     []string
	keyRequests map[string]map[string]any
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		transit:     map[string]*ecdsa.PrivateKey{},
		audit:       map[string]any{},
		keyRequests: map[string]map[string]any{},
		token:       "root",
		mounts:      map[string]any{"sys/": map[string]any{"type": "system"}},
		auths:       map[string]any{"token/": map[string]any{"type": "token"}},
		configs:     map[string]map[string]any{},
		policies:    map[string]string{},
		roles:       map[string]map[string]any{},
		secrets:     map[string]map[string]string{},
	}
}

// listing answers the way Vault does: the entries under "data", and again at
// the top level beside fields that are not entries at all.
func (f *fakeVault) listing(entries map[string]any) map[string]any {
	out := map[string]any{"request_id": "0000", "lease_duration": 0, "data": entries}
	maps.Copy(out, entries)
	return out
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != f.token {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case path == "sys/mounts" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(f.listing(f.mounts))
	case strings.HasPrefix(path, "sys/mounts/"):
		f.mounts[strings.TrimPrefix(path, "sys/mounts/")+"/"] = body
		f.enabled++
	case path == "sys/auth" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(f.listing(f.auths))
	case strings.HasPrefix(path, "sys/auth/"):
		f.auths[strings.TrimPrefix(path, "sys/auth/")+"/"] = body
		f.enabled++
	case path == "auth/token/lookup-self":
		_, _ = w.Write([]byte(`{"data":{}}`))
	case strings.HasPrefix(path, "auth/") && strings.HasSuffix(path, "/config"):
		f.configs[strings.TrimSuffix(strings.TrimPrefix(path, "auth/"), "/config")] = body
	case strings.HasPrefix(path, "sys/policies/acl/"):
		name := strings.TrimPrefix(path, "sys/policies/acl/")
		if r.Method == http.MethodGet {
			policy, ok := f.policies[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policy": policy}})
			return
		}
		f.policies[name], _ = body["policy"].(string)
	case path == "sys/audit" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{"data": f.audit})
	case strings.HasPrefix(path, "sys/audit/"):
		f.audit[strings.TrimPrefix(path, "sys/audit/")+"/"] = body
	case strings.HasPrefix(path, "auth/") && strings.Contains(path, "/role/"):
		if r.Method == http.MethodDelete {
			delete(f.roles, strings.TrimPrefix(path, "auth/"))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		f.roles[strings.TrimPrefix(path, "auth/")] = body
	case strings.HasPrefix(path, "transit/keys/"):
		name := strings.TrimPrefix(path, "transit/keys/")
		if r.Method == http.MethodGet {
			key, ok := f.transit[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
			public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "ecdsa-p256", "exportable": false, "deletion_allowed": false, "latest_version": 1,
				"keys": map[string]any{"1": map[string]any{
					"public_key": public, "creation_time": "2026-10-11T20:18:04Z",
				}},
			}})
			return
		}
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		f.transit[name] = key
		f.created = append(f.created, name)
		f.keyRequests[name] = body
	case strings.HasPrefix(path, "transit/sign/"):
		key := f.transit[strings.TrimPrefix(path, "transit/sign/")]
		digest, _ := base64.StdEncoding.DecodeString(body["input"].(string))
		if key == nil || body["prehashed"] != true || body["marshaling_algorithm"] != "asn1" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":["bad sign request"]}`))
			return
		}
		signature, _ := ecdsa.SignASN1(rand.Reader, key, digest)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(signature),
		}})
	case strings.HasPrefix(path, "secret/data/"):
		name := strings.TrimPrefix(path, "secret/data/")
		if r.Method == http.MethodGet {
			fields, ok := f.secrets[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": fields}})
			return
		}
		fields := map[string]string{}
		for k, v := range body["data"].(map[string]any) {
			fields[k], _ = v.(string)
		}
		f.secrets[name] = fields
	default:
		http.NotFound(w, r)
	}
}

func clientFor(t *testing.T, fake *fakeVault) *vaultClient {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return &vaultClient{base: server.URL, token: fake.token, http: server.Client()}
}

// The store may read the secure software supply chain's secrets and nothing else, and only
// one ServiceAccount is given that. Configuring twice changes nothing.
func TestConfigureKubernetesAuth(t *testing.T) {
	fake := newFakeVault()
	vault := clientFor(t, fake)
	ctx := context.Background()

	for range 2 {
		if err := ensureSecretEngine(ctx, vault); err != nil {
			t.Fatal(err)
		}
		if err := configureKubernetesAuth(ctx, vault); err != nil {
			t.Fatal(err)
		}
	}
	if fake.enabled != 2 {
		t.Errorf("the engine and the auth method were enabled %d times in two runs, want once each", fake.enabled)
	}
	engine, _ := fake.mounts["secret/"].(map[string]any)
	if engine["type"] != "kv" || engine["options"].(map[string]any)["version"] != "2" {
		t.Errorf("secret/ = %v, want a version 2 key-value engine", engine)
	}
	if got := fake.configs["kubernetes"]; got["kubernetes_host"] != "https://kubernetes.default.svc" {
		t.Errorf("Kubernetes auth config = %v", got)
	}

	policy := fake.policies[vaultPolicy]
	if !strings.Contains(policy, `path "secret/data/supplychain/*"`) || !strings.Contains(policy, `["read"]`) {
		t.Errorf("policy does not grant read on the secure software supply chain's secrets:\n%s", policy)
	}
	for _, more := range []string{"create", "update", "delete", "list", "sudo", `"*"`} {
		if strings.Contains(policy, more) {
			t.Errorf("policy grants more than read (%s):\n%s", more, policy)
		}
	}
	if strings.Count(policy, "path ") != 1 {
		t.Errorf("policy covers more than one path:\n%s", policy)
	}

	role := fake.roles["kubernetes/role/"+vaultRole]
	if got := role["bound_service_account_names"]; !reflect.DeepEqual(got, []any{vaultServiceAccount}) {
		t.Errorf("role is bound to ServiceAccounts %v, want only %s", got, vaultServiceAccount)
	}
	if got := role["bound_service_account_namespaces"]; !reflect.DeepEqual(got, []any{vaultNamespace}) {
		t.Errorf("role is bound to namespaces %v, want only %s", got, vaultNamespace)
	}
	if got := role["token_policies"]; !reflect.DeepEqual(got, []any{vaultPolicy}) {
		t.Errorf("role gives policies %v, want only %s", got, vaultPolicy)
	}
}

// Each of the store's keys is one secret holding one value. Setting one key
// leaves the others as they are, and a key that is not set reads as empty.
func TestVaultReadAndWrite(t *testing.T) {
	fake := newFakeVault()
	vault := clientFor(t, fake)
	ctx := context.Background()

	if got, err := vault.read(ctx, store.GitPrivateKey); err != nil || got != "" {
		t.Fatalf("a key that is not set read as %q, %v; want empty and no error", got, err)
	}
	if err := vault.write(ctx, store.GitPrivateKey, "first\nkey\n"); err != nil {
		t.Fatal(err)
	}
	if err := vault.write(ctx, store.GitKnownHosts, "hosts"); err != nil {
		t.Fatal(err)
	}
	if err := vault.write(ctx, store.GitPrivateKey, "rotated\nkey\n"); err != nil {
		t.Fatal(err)
	}
	if got, _ := vault.read(ctx, store.GitPrivateKey); got != "rotated\nkey\n" {
		t.Errorf("after rotating, the key reads %q", got)
	}
	if got, _ := vault.read(ctx, store.GitKnownHosts); got != "hosts" {
		t.Errorf("rotating one key changed another: %q", got)
	}
}

// The store carries no credential: it names a ServiceAccount, and Vault
// decides what that ServiceAccount may read.
func TestSecretStoreLogsInWithAServiceAccount(t *testing.T) {
	obj := secretStore()
	if obj.GetName() != store.Name || obj.GetKind() != store.Kind {
		t.Fatalf("store is %s %s", obj.GetKind(), obj.GetName())
	}
	vault, _, _ := unstructured.NestedMap(obj.Object, "spec", "provider", "vault")
	if vault["server"] != vaultAddress || vault["path"] != store.Mount || vault["version"] != "v2" {
		t.Errorf("provider = %v", vault)
	}
	auth, _, _ := unstructured.NestedMap(obj.Object, "spec", "provider", "vault", "auth")
	if len(auth) != 1 {
		t.Errorf("store has auth methods %v, want only kubernetes", auth)
	}
	kubernetes, _, _ := unstructured.NestedMap(auth, "kubernetes")
	ref, _, _ := unstructured.NestedStringMap(kubernetes, "serviceAccountRef")
	if kubernetes["role"] != vaultRole || ref["name"] != vaultServiceAccount || ref["namespace"] != vaultNamespace {
		t.Errorf("kubernetes auth = %v", kubernetes)
	}
	raw, _ := json.Marshal(obj.Object)
	for _, forbidden := range []string{"tokenSecretRef", "secretRef", "password"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("the store refers to a stored credential (%s)", forbidden)
		}
	}
}

// The manifests start Vault; what can only be made once is not in them.
func TestVaultManifests(t *testing.T) {
	data, err := manifests.Dependencies.ReadFile("dependencies/vault/server/vault.yaml")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := manifests.Dependencies.ReadFile("dependencies/vault/identity/identity.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// The ServiceAccount the store logs in as is needed with any Vault, so it
	// is not in the manifests that are skipped when Vault runs elsewhere.
	if !strings.Contains(string(identity), "name: "+vaultServiceAccount) ||
		strings.Contains(string(data), "name: "+vaultServiceAccount) {
		t.Errorf("ServiceAccount %s must be in the identity manifest and only there", vaultServiceAccount)
	}
	manifest := string(data)
	for _, want := range []string{
		"kind: StatefulSet", "volumeClaimTemplates:",
		"secretName: " + vaultKeysSecret, "optional: true", "system:auth-delegator",
	} {
		if !strings.Contains(manifest, want) {
			t.Errorf("Vault manifest does not contain %q", want)
		}
	}
	for _, obj := range decodeAll(t, "dependencies/vault/server/vault.yaml") {
		if obj.GetKind() == "Secret" {
			t.Errorf("the manifests ship Secret %s; Vault's keys are made by the installer, once", obj.GetName())
		}
	}
	if strings.Contains(manifest, "-dev") {
		t.Error("Vault is started in dev mode, which keeps everything in memory")
	}
}

func TestParseAssignments(t *testing.T) {
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("line one\nline two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseAssignments([]string{"github/token=abc=def", "git/ssh-privatekey=@" + file})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"github/token": "abc=def", "git/ssh-privatekey": "line one\nline two\n"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed %v, want %v", got, want)
	}
	for _, bad := range [][]string{nil, {"novalue"}, {"=x"}, {"empty="}, {"file=@" + file + ".missing"}} {
		if _, err := parseAssignments(bad); err == nil {
			t.Errorf("parseAssignments(%v) succeeded", bad)
		}
	}
}

// With a store of one's own, the installer runs no Vault.
func TestExternalSecretStoreSkipsVault(t *testing.T) {
	i := &Installer{opts: Options{ExternalSecretStore: true}}
	steps, err := i.stepsToRun()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if s.Name == "Vault" || s.Name == "Secret Store" {
			t.Errorf("step %q runs although the store is provided by the user", s.Name)
		}
	}
}

// With a Vault that already exists, the installer runs none of its own but
// still sets up the store; by default it does both.
func TestExistingVaultIsConfiguredNotInstalled(t *testing.T) {
	names := func(opts Options) map[string]bool {
		t.Helper()
		steps, err := (&Installer{opts: opts}).stepsToRun()
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, s := range steps {
			out[s.Name] = true
		}
		return out
	}
	if got := names(Options{VaultAddr: "http://vault.example:8200"}); got["Vault"] || !got["Secret Store"] {
		t.Errorf("with --vault-addr: Vault step %v, Secret Store step %v; want false, true",
			got["Vault"], got["Secret Store"])
	}
	if got := names(Options{}); !got["Vault"] || !got["Secret Store"] {
		t.Errorf("by default: Vault step %v, Secret Store step %v; want both", got["Vault"], got["Secret Store"])
	}
}

// A Vault outside the cluster verifies tokens itself. It must accept only
// this cluster's issuer, only tokens made for Vault, and only the one
// ServiceAccount.
func TestConfigureJWTAuth(t *testing.T) {
	fake := newFakeVault()
	vault := clientFor(t, fake)
	ctx := context.Background()
	keys := []string{"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"}

	for range 2 {
		if err := configureJWTAuth(ctx, vault, "https://kubernetes.default.svc.cluster.local", keys); err != nil {
			t.Fatal(err)
		}
	}
	if fake.enabled != 1 {
		t.Errorf("the auth method was enabled %d times in two runs, want once", fake.enabled)
	}
	if method, _ := fake.auths[vaultJWTAuthMount+"/"].(map[string]any); method["type"] != "jwt" {
		t.Errorf("auth method at %s/ = %v, want jwt", vaultJWTAuthMount, method)
	}
	config := fake.configs[vaultJWTAuthMount]
	if config["bound_issuer"] != "https://kubernetes.default.svc.cluster.local" ||
		!reflect.DeepEqual(config["jwt_validation_pubkeys"], []any{keys[0]}) {
		t.Errorf("JWT auth config = %v", config)
	}
	role := fake.roles[vaultJWTAuthMount+"/role/"+vaultRole]
	want := map[string]any{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"bound_subject":   "system:serviceaccount:vault:supply-chain-secrets",
		"bound_audiences": []any{vaultJWTAudience},
		"token_policies":  []any{vaultPolicy},
		"token_ttl":       "1h",
	}
	if !reflect.DeepEqual(role, want) {
		t.Errorf("role = %v, want %v", role, want)
	}

	// A mount of that name that is something else belongs to someone else.
	fake.auths["taken/"] = map[string]any{"type": "userpass"}
	if err := ensureAuthMethod(ctx, vault, "taken", "jwt"); err == nil {
		t.Error("an auth method of another type was taken over")
	}
}

// The engine has to be version 2: the store reads secret/data/..., which a
// version 1 engine does not have.
func TestEnsureSecretEngineRefusesTheWrongKind(t *testing.T) {
	fake := newFakeVault()
	fake.mounts["secret/"] = map[string]any{"type": "kv", "options": map[string]any{"version": "1"}}
	if err := ensureSecretEngine(context.Background(), clientFor(t, fake)); err == nil {
		t.Error("a version 1 key-value engine was accepted")
	}
	fake.mounts["secret/"] = map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}
	if err := ensureSecretEngine(context.Background(), clientFor(t, fake)); err != nil {
		t.Errorf("an existing version 2 engine was refused: %v", err)
	}
	if fake.enabled != 0 {
		t.Error("an existing engine was mounted again")
	}
}

// The store for an outside Vault names its address and logs in with a token
// made for Vault; it still holds no credential.
func TestExternalSecretStore(t *testing.T) {
	obj := externalSecretStore("http://vault.example:8200")
	vault, _, _ := unstructured.NestedMap(obj.Object, "spec", "provider", "vault")
	if vault["server"] != "http://vault.example:8200" {
		t.Errorf("server = %v", vault["server"])
	}
	auth, _, _ := unstructured.NestedMap(obj.Object, "spec", "provider", "vault", "auth")
	if len(auth) != 1 {
		t.Fatalf("auth methods = %v, want only jwt", auth)
	}
	token, _, _ := unstructured.NestedMap(auth, "jwt", "kubernetesServiceAccountToken")
	ref, _, _ := unstructured.NestedStringMap(token, "serviceAccountRef")
	if ref["name"] != vaultServiceAccount || ref["namespace"] != vaultNamespace ||
		!reflect.DeepEqual(token["audiences"], []any{vaultJWTAudience}) {
		t.Errorf("token request = %v", token)
	}
	raw, _ := json.Marshal(obj.Object)
	for _, forbidden := range []string{"tokenSecretRef", "secretRef", "password"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("the store refers to a stored credential (%s)", forbidden)
		}
	}
}

func TestPublicKeysFromJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
		"n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes()),
	}}})
	keys, err := publicKeysFromJWKS(jwks)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %v, err = %v", keys, err)
	}
	block, _ := pem.Decode([]byte(keys[0]))
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := parsed.(*rsa.PublicKey); !ok || got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Error("the PEM key is not the key in the set")
	}
	for _, bad := range []string{`{"keys":[]}`, `{"keys":[{"kty":"oct"}]}`, `not json`} {
		if _, err := publicKeysFromJWKS([]byte(bad)); err == nil {
			t.Errorf("publicKeysFromJWKS(%s) succeeded", bad)
		}
	}
}

// The sample in config/samples is the store as documentation; the installer
// builds the real one. They must describe the same thing.
func TestSampleStoreMatchesWhatTheInstallerCreates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples",
		"externalsecrets_v1_clustersecretstore_vault.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sample := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(data, &sample.Object); err != nil {
		t.Fatal(err)
	}
	created := secretStore()
	if sample.GetName() != created.GetName() || sample.GetKind() != created.GetKind() ||
		sample.GetAPIVersion() != created.GetAPIVersion() {
		t.Errorf("sample is %s %s %s", sample.GetAPIVersion(), sample.GetKind(), sample.GetName())
	}
	if !reflect.DeepEqual(sample.Object["spec"], created.Object["spec"]) {
		t.Errorf("sample spec %v differs from the installer's %v", sample.Object["spec"], created.Object["spec"])
	}
	// The comment in the sample lists every key the operator asks for.
	for _, entry := range store.Keys {
		if !strings.Contains(string(data), entry.Key) {
			t.Errorf("the sample does not mention %q", entry.Key)
		}
	}
}

// The Vault step and the Secret Store step are each run on their own: the
// first is skipped for a Vault somewhere else, and either can be re-run by
// naming it as a package. Each therefore has to bring the namespace its
// objects are in.
func TestEachVaultStepDeclaresItsNamespace(t *testing.T) {
	for _, file := range []string{"dependencies/vault/server/vault.yaml", "dependencies/vault/identity/identity.yaml"} {
		data, err := manifests.Dependencies.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "kind: Namespace\nmetadata:\n  name: vault\n") {
			t.Errorf("%s does not declare the vault namespace", file)
		}
	}
}

// With SPIFFE, Vault accepts one identity: the JWT-SVID SPIRE issues to the
// secrets ServiceAccount, made for Vault. The Kubernetes login an earlier
// install set up is removed, so nothing else gets in.
func TestConfigureSPIFFEAuth(t *testing.T) {
	fake := newFakeVault()
	vault := clientFor(t, fake)
	ctx := context.Background()

	if err := configureKubernetesAuth(ctx, vault); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := configureSPIFFEAuth(ctx, vault, "your-domain.example", "the CA"); err != nil {
			t.Fatal(err)
		}
	}
	config := fake.configs[vaultSPIFFEAuthMount]
	if config["oidc_discovery_url"] != spireOIDCIssuer || config["bound_issuer"] != spireOIDCIssuer ||
		config["oidc_discovery_ca_pem"] != "the CA" || !strings.HasPrefix(spireOIDCIssuer, "https://") {
		t.Errorf("JWT auth config = %v, want SPIRE's OIDC discovery", config)
	}
	want := map[string]any{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"bound_subject":   "spiffe://your-domain.example/ns/vault/sa/supply-chain-secrets",
		"bound_audiences": []any{"vault"},
		"token_policies":  []any{vaultPolicy},
		"token_ttl":       "10m",
	}
	if role := fake.roles[vaultSPIFFEAuthMount+"/role/"+vaultRole]; !reflect.DeepEqual(role, want) {
		t.Errorf("role = %v, want %v", role, want)
	}
	if role, ok := fake.roles[vaultAuthMount+"/role/"+vaultRole]; ok {
		t.Errorf("the Kubernetes login is still there: %v", role)
	}
}

func TestSPIFFESecretStore(t *testing.T) {
	auth, _, _ := unstructured.NestedMap(spiffeSecretStore().Object, "spec", "provider", "vault", "auth")
	want := map[string]any{"jwt": map[string]any{
		"path": "jwt",
		"role": vaultRole,
		"secretRef": map[string]any{
			"name": "supply-chain-vault-jwt", "namespace": "vault", "key": "jwt",
		},
	}}
	if !reflect.DeepEqual(auth, want) {
		t.Errorf("auth = %v, want %v", auth, want)
	}
}

// The SPIFFE login is for the Vault this cluster runs. A Vault elsewhere
// cannot reach SPIRE's discovery endpoint, and a store of the user's own is
// not ours to configure.
func TestSPIFFELoginOnlyForTheBuiltInVault(t *testing.T) {
	for _, tc := range []struct {
		opts Options
		want bool
	}{
		{Options{SigningIdentity: IdentitySPIFFE}, true},
		{Options{SigningIdentity: IdentityKubernetes}, false},
		{Options{SigningIdentity: IdentitySPIFFE, VaultAddr: "http://vault.example:8200"}, false},
		{Options{SigningIdentity: IdentitySPIFFE, ExternalSecretStore: true}, false},
	} {
		i := &Installer{opts: tc.opts}
		if got := i.spiffeLogin(); got != tc.want {
			t.Errorf("spiffeLogin with %+v = %v, want %v", tc.opts, got, tc.want)
		}
	}
}

// The bridge, the SPIRE entry and Vault's role have to name the same
// ServiceAccount, Secret and audience, in three different files.
func TestSPIFFEBridgeMatchesTheStore(t *testing.T) {
	bridge, err := manifests.Dependencies.ReadFile("dependencies/vault/spiffe/svid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"serviceAccountName: " + vaultServiceAccount,
		"name: " + vaultSPIFFEBridge,
		"secrets/" + vaultSPIFFESecret + "?",
		`\"` + vaultSPIFFESecretKey + `\":`,
		`jwt_audience = "` + vaultJWTAudience + `"`,
	} {
		if !strings.Contains(string(bridge), want) {
			t.Errorf("the bridge manifest does not contain %q", want)
		}
	}
	identities, err := manifests.Dependencies.ReadFile("dependencies/spire/identities/identities.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(identities), secretsSPIFFEID(trustDomainPlaceholder)) {
		t.Errorf("SPIRE has no entry for %s", secretsSPIFFEID(trustDomainPlaceholder))
	}
}

func TestSPIFFESampleStoreMatchesWhatTheInstallerCreates(t *testing.T) {
	data, err := os.ReadFile("../../../config/samples/externalsecrets_v1_clustersecretstore_vault_spiffe.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sample := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(data, &sample.Object); err != nil {
		t.Fatal(err)
	}
	if created := spiffeSecretStore(); !reflect.DeepEqual(sample.Object["spec"], created.Object["spec"]) {
		t.Errorf("sample spec %v differs from the installer's %v", sample.Object["spec"], created.Object["spec"])
	}
	for _, entry := range store.Keys {
		if !strings.Contains(string(data), entry.Key) {
			t.Errorf("the sample does not mention %q", entry.Key)
		}
	}
}
