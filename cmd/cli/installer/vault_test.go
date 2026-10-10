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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/store"
)

// fakeVault keeps what the installer configures and what is written to the
// key-value engine, and counts how often each thing was created.
type fakeVault struct {
	token    string
	mounts   map[string]any
	auths    map[string]any
	config   map[string]any
	policies map[string]string
	roles    map[string]map[string]any
	secrets  map[string]map[string]string
	enabled  int
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		token:    "root",
		mounts:   map[string]any{"sys/": struct{}{}},
		auths:    map[string]any{"token/": struct{}{}},
		policies: map[string]string{},
		roles:    map[string]map[string]any{},
		secrets:  map[string]map[string]string{},
	}
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
		_ = json.NewEncoder(w).Encode(f.mounts)
	case strings.HasPrefix(path, "sys/mounts/"):
		f.mounts[strings.TrimPrefix(path, "sys/mounts/")+"/"] = body
		f.enabled++
	case path == "sys/auth" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(f.auths)
	case strings.HasPrefix(path, "sys/auth/"):
		f.auths[strings.TrimPrefix(path, "sys/auth/")+"/"] = body
		f.enabled++
	case path == "auth/kubernetes/config":
		f.config = body
	case strings.HasPrefix(path, "sys/policies/acl/"):
		f.policies[strings.TrimPrefix(path, "sys/policies/acl/")], _ = body["policy"].(string)
	case strings.HasPrefix(path, "auth/kubernetes/role/"):
		f.roles[strings.TrimPrefix(path, "auth/kubernetes/role/")] = body
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

// The store may read the supply chain's secrets and nothing else, and only
// one ServiceAccount is given that. Configuring twice changes nothing.
func TestConfigureVault(t *testing.T) {
	fake := newFakeVault()
	vault := clientFor(t, fake)
	ctx := context.Background()

	for range 2 {
		if err := configureVault(ctx, vault); err != nil {
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
	if fake.config["kubernetes_host"] != "https://kubernetes.default.svc" {
		t.Errorf("Kubernetes auth config = %v", fake.config)
	}

	policy := fake.policies[vaultPolicy]
	if !strings.Contains(policy, `path "secret/data/supplychain/*"`) || !strings.Contains(policy, `["read"]`) {
		t.Errorf("policy does not grant read on the supply chain's secrets:\n%s", policy)
	}
	for _, more := range []string{"create", "update", "delete", "list", "sudo", `"*"`} {
		if strings.Contains(policy, more) {
			t.Errorf("policy grants more than read (%s):\n%s", more, policy)
		}
	}
	if strings.Count(policy, "path ") != 1 {
		t.Errorf("policy covers more than one path:\n%s", policy)
	}

	role := fake.roles[vaultRole]
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

// The key-value engine replaces a secret whole. Setting one field must not
// lose the others: rotating the registry password should not delete a key.
func TestVaultWriteKeepsOtherFields(t *testing.T) {
	fake := newFakeVault()
	vault := clientFor(t, fake)
	ctx := context.Background()

	if got, err := vault.read(ctx, store.Git); err != nil || len(got) != 0 {
		t.Fatalf("a secret that does not exist read as %v, %v; want no fields and no error", got, err)
	}
	first := map[string]string{store.GitPrivateKey: "key-1", store.GitKnownHosts: "hosts"}
	if err := vault.write(ctx, store.Git, first); err != nil {
		t.Fatal(err)
	}
	if err := vault.write(ctx, store.Git, map[string]string{store.GitPrivateKey: "key-2"}); err != nil {
		t.Fatal(err)
	}
	got, err := vault.read(ctx, store.Git)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{store.GitPrivateKey: "key-2", store.GitKnownHosts: "hosts"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("after rotating one field the secret is %v, want %v", got, want)
	}

	vault.token = "wrong"
	if _, err := vault.read(ctx, store.Git); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("a refused read returned %v, want Vault's reason", err)
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
	data, err := manifests.Dependencies.ReadFile("dependencies/vault/vault.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(data)
	for _, want := range []string{
		"kind: StatefulSet", "volumeClaimTemplates:", "name: " + vaultServiceAccount,
		"secretName: " + vaultKeysSecret, "optional: true", "system:auth-delegator",
	} {
		if !strings.Contains(manifest, want) {
			t.Errorf("Vault manifest does not contain %q", want)
		}
	}
	for _, obj := range decodeAll(t, "dependencies/vault/vault.yaml") {
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
	got, err := parseAssignments([]string{"token=abc=def", "ssh-privatekey=@" + file})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"token": "abc=def", "ssh-privatekey": "line one\nline two\n"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed %v, want %v", got, want)
	}
	for _, bad := range [][]string{nil, {"novalue"}, {"=x"}, {"empty="}, {"file=@" + file + ".missing"}} {
		if _, err := parseAssignments(bad); err == nil {
			t.Errorf("parseAssignments(%v) succeeded", bad)
		}
	}
}

func TestStepsToRunOnlyStep(t *testing.T) {
	i := &Installer{opts: Options{OnlyStep: "vault"}}
	steps, err := i.stepsToRun()
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].Name != "Vault" {
		t.Errorf("steps = %v, want only Vault", steps)
	}
	i.opts.OnlyStep = "no such step"
	if _, err := i.stepsToRun(); err == nil {
		t.Error("an unknown step was accepted")
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
		if s.Name == "Vault" {
			t.Error("the Vault step runs although the store is provided by the user")
		}
	}
	i.opts.ExternalSecretStore = false
	steps, _ = i.stepsToRun()
	found := false
	for _, s := range steps {
		found = found || s.Name == "Vault"
	}
	if !found {
		t.Error("the Vault step is missing from a default install")
	}
}
