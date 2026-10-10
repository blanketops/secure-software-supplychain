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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/store"
)

const (
	vaultNamespace = "vault"
	vaultPod       = "vault-0"
	vaultSTS       = "vault"
	vaultPort      = 8200
	// vaultAddress is where the cluster reaches Vault.
	vaultAddress = "http://vault.vault.svc.cluster.local:8200"

	// vaultKeysSecret holds what initialising Vault returns: the key that
	// unseals it and the root token. See dependencies/vault/vault.yaml for
	// what keeping them in the cluster means.
	vaultKeysSecret   = "vault-unseal"
	vaultUnsealKeyKey = "unseal-key"
	vaultRootTokenKey = "root-token"

	// How External Secrets logs in, and what it may then do.
	vaultAuthMount      = "kubernetes"
	vaultRole           = "supply-chain"
	vaultPolicy         = "supply-chain-read"
	vaultServiceAccount = "supply-chain-secrets"
)

var podGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}

// vaultReadPolicy lets its holder read the supply chain's secrets and nothing
// else: not write them, not list or read anything outside their folder.
func vaultReadPolicy() string {
	return fmt.Sprintf("path \"%s/data/%s/*\" {\n  capabilities = [\"read\"]\n}\n", store.Mount, store.Prefix)
}

// vaultClient is the little of Vault's HTTP API the installer needs.
type vaultClient struct {
	base  string
	token string
	http  *http.Client
}

// call makes one request. A nil out discards the response body.
func (v *vaultClient) call(ctx context.Context, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.base+path, body)
	if err != nil {
		return 0, err
	}
	if v.token != "" {
		req.Header.Set("X-Vault-Token", v.token)
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 400 {
		var failure struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &failure)
		return resp.StatusCode, fmt.Errorf("vault %s %s: HTTP %d: %s",
			method, path, resp.StatusCode, strings.Join(failure.Errors, "; "))
	}
	if out != nil && len(data) > 0 {
		return resp.StatusCode, json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

// read returns the fields of one secret. A secret that does not exist has no
// fields; that is not an error.
func (v *vaultClient) read(ctx context.Context, path string) (map[string]string, error) {
	var got struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	status, err := v.call(ctx, http.MethodGet, "/v1/"+store.Mount+"/data/"+path, nil, &got)
	if status == http.StatusNotFound {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if got.Data.Data == nil {
		return map[string]string{}, nil
	}
	return got.Data.Data, nil
}

// write sets fields of one secret and keeps the fields it does not name. The
// key-value engine replaces a secret whole, so what is there is read first.
func (v *vaultClient) write(ctx context.Context, path string, fields map[string]string) error {
	merged, err := v.read(ctx, path)
	if err != nil {
		return err
	}
	maps.Copy(merged, fields)
	_, err = v.call(ctx, http.MethodPost, "/v1/"+store.Mount+"/data/"+path, map[string]any{"data": merged}, nil)
	return err
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

// ensureVault brings the Vault the manifests started to the point where
// External Secrets can read the supply chain's secrets from it. Every part of
// it can be run again: Vault is initialised once, and its keys are never
// replaced, because nothing else can open the storage they protect.
func (i *Installer) ensureVault(ctx context.Context) error {
	vault, stop, err := i.connectToVault(ctx)
	if err != nil {
		return err
	}
	defer stop()

	unsealKey, rootToken, err := i.initialiseVault(ctx, vault)
	if err != nil {
		return err
	}
	var seal struct {
		Sealed bool `json:"sealed"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/seal-status", nil, &seal); err != nil {
		return err
	}
	if seal.Sealed {
		if _, err := vault.call(ctx, http.MethodPut, "/v1/sys/unseal", map[string]any{"key": unsealKey}, &seal); err != nil {
			return fmt.Errorf("unsealing Vault: %w", err)
		}
		if seal.Sealed {
			return errors.New("vault is still sealed after its key was given")
		}
	}
	vault.token = rootToken

	if err := configureVault(ctx, vault); err != nil {
		return err
	}
	if err := i.applyObject(ctx, secretStore()); err != nil {
		if meta.IsNoMatchError(err) {
			return fmt.Errorf("the External Secrets Operator is not installed; install it, then run this step again: %w", err)
		}
		return fmt.Errorf("creating ClusterSecretStore %s: %w", store.Name, err)
	}
	return i.waitForStatefulSet(ctx, vaultNamespace, vaultSTS, readyTimeout)
}

// initialiseVault returns Vault's unseal key and root token: fresh ones from
// initialising it, which are then stored, or the stored ones if it already
// was.
func (i *Installer) initialiseVault(ctx context.Context, vault *vaultClient) (unsealKey, rootToken string, err error) {
	var state struct {
		Initialized bool `json:"initialized"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/init", nil, &state); err != nil {
		return "", "", err
	}
	secrets := i.dynamic.Resource(secretGVR).Namespace(vaultNamespace)

	if state.Initialized {
		unsealKey, err = i.readSecretValue(ctx, vaultNamespace, vaultKeysSecret, vaultUnsealKeyKey)
		if err != nil {
			return "", "", fmt.Errorf("vault is initialised but its keys are not in Secret %s/%s; "+
				"without them it cannot be unsealed or configured: %w", vaultNamespace, vaultKeysSecret, err)
		}
		rootToken, err = i.readSecretValue(ctx, vaultNamespace, vaultKeysSecret, vaultRootTokenKey)
		return unsealKey, rootToken, err
	}

	// One key share: the sidecar unseals with a single key. Vault can be
	// rekeyed to more shares when the key is taken out of the cluster.
	var created struct {
		Keys      []string `json:"keys_base64"`
		RootToken string   `json:"root_token"`
	}
	request := map[string]any{"secret_shares": 1, "secret_threshold": 1}
	if _, err := vault.call(ctx, http.MethodPut, "/v1/sys/init", request, &created); err != nil {
		return "", "", fmt.Errorf("initialising Vault: %w", err)
	}
	if len(created.Keys) != 1 || created.RootToken == "" {
		return "", "", errors.New("initialising Vault returned no key")
	}
	secret := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      vaultKeysSecret,
			"namespace": vaultNamespace,
			"labels":    map[string]any{"blanketops.dev/managed": "true"},
		},
		"type": "Opaque",
		"stringData": map[string]any{
			vaultUnsealKeyKey: created.Keys[0],
			vaultRootTokenKey: created.RootToken,
		},
	}}
	// These are returned exactly once. If they cannot be stored, say so
	// loudly: the Vault just created can never be opened again.
	if _, err := secrets.Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return "", "", fmt.Errorf("vault was initialised but its keys could not be stored in Secret %s/%s; "+
			"delete the vault StatefulSet and its volume and run this step again: %w", vaultNamespace, vaultKeysSecret, err)
	}
	return created.Keys[0], created.RootToken, nil
}

// configureVault turns on what the store needs: a key-value engine, Kubernetes
// auth, a policy that can read the supply chain's secrets, and a role that
// gives that policy to one ServiceAccount.
func configureVault(ctx context.Context, vault *vaultClient) error {
	var mounts map[string]json.RawMessage
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/mounts", nil, &mounts); err != nil {
		return fmt.Errorf("listing Vault's secret engines: %w", err)
	}
	if _, ok := mounts[store.Mount+"/"]; !ok {
		engine := map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}
		if _, err := vault.call(ctx, http.MethodPost, "/v1/sys/mounts/"+store.Mount, engine, nil); err != nil {
			return fmt.Errorf("enabling the key-value engine: %w", err)
		}
	}

	var auths map[string]json.RawMessage
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/auth", nil, &auths); err != nil {
		return fmt.Errorf("listing Vault's auth methods: %w", err)
	}
	if _, ok := auths[vaultAuthMount+"/"]; !ok {
		method := map[string]any{"type": "kubernetes"}
		if _, err := vault.call(ctx, http.MethodPost, "/v1/sys/auth/"+vaultAuthMount, method, nil); err != nil {
			return fmt.Errorf("enabling Kubernetes auth: %w", err)
		}
	}
	// Running in the cluster, Vault verifies tokens with its own
	// ServiceAccount and the cluster's CA; it only needs to be told where
	// the API server is.
	config := map[string]any{"kubernetes_host": "https://kubernetes.default.svc"}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/auth/"+vaultAuthMount+"/config", config, nil); err != nil {
		return fmt.Errorf("configuring Kubernetes auth: %w", err)
	}

	policy := map[string]any{"policy": vaultReadPolicy()}
	if _, err := vault.call(ctx, http.MethodPut, "/v1/sys/policies/acl/"+vaultPolicy, policy, nil); err != nil {
		return fmt.Errorf("writing policy %s: %w", vaultPolicy, err)
	}
	role := map[string]any{
		"bound_service_account_names":      []string{vaultServiceAccount},
		"bound_service_account_namespaces": []string{vaultNamespace},
		"token_policies":                   []string{vaultPolicy},
		"token_ttl":                        "1h",
	}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/auth/"+vaultAuthMount+"/role/"+vaultRole, role, nil); err != nil {
		return fmt.Errorf("writing role %s: %w", vaultRole, err)
	}
	return nil
}

// secretStore is the ClusterSecretStore every ExternalSecret of the operator
// reads from. It holds no credential: External Secrets logs in to Vault as a
// ServiceAccount, and Vault gives that ServiceAccount a short-lived token.
func secretStore() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "external-secrets.io/v1",
		"kind":       store.Kind,
		"metadata": map[string]any{
			"name":   store.Name,
			"labels": map[string]any{"blanketops.dev/managed": "true"},
		},
		"spec": map[string]any{
			"provider": map[string]any{
				"vault": map[string]any{
					"server":  vaultAddress,
					"path":    store.Mount,
					"version": "v2",
					"auth": map[string]any{
						"kubernetes": map[string]any{
							"mountPath": vaultAuthMount,
							"role":      vaultRole,
							"serviceAccountRef": map[string]any{
								"name":      vaultServiceAccount,
								"namespace": vaultNamespace,
							},
						},
					},
				},
			},
		},
	}}
}

// connectToVault waits for the Vault server to be up and returns a client for
// it and a func that closes the connection.
//
// A port-forward belongs to one pod. When the StatefulSet has just been
// changed the pod is replaced under it, so each attempt opens a new one
// instead of waiting on a connection to a pod that is gone.
func (i *Installer) connectToVault(ctx context.Context) (*vaultClient, func(), error) {
	deadline := time.Now().Add(readyTimeout)
	var last error
	for time.Now().Before(deadline) {
		if i.vaultServerRunning(ctx) {
			base, stop, err := i.forwardToPod(ctx, vaultNamespace, vaultPod, vaultPort)
			if err == nil {
				vault := &vaultClient{base: base, http: &http.Client{Timeout: 30 * time.Second}}
				if _, err = vault.call(ctx, http.MethodGet, "/v1/sys/seal-status", nil, nil); err == nil {
					return vault, stop, nil
				}
				stop()
			}
			last = err
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return nil, nil, fmt.Errorf("vault did not come up within %s: %v", readyTimeout, last)
}

// vaultServerRunning reports whether the Vault container of the current pod
// has started. The pod is not Ready until Vault is unsealed, and it is the
// installer that unseals it, so readiness cannot be what is waited for.
func (i *Installer) vaultServerRunning(ctx context.Context) bool {
	pod, err := i.dynamic.Resource(podGVR).Namespace(vaultNamespace).Get(ctx, vaultPod, metav1.GetOptions{})
	if err != nil || pod.GetDeletionTimestamp() != nil {
		return false
	}
	statuses, _, _ := unstructured.NestedSlice(pod.Object, "status", "containerStatuses")
	for _, raw := range statuses {
		status, ok := raw.(map[string]any)
		if !ok || status["name"] != "vault" {
			continue
		}
		_, running, _ := unstructured.NestedMap(status, "state", "running")
		return running
	}
	return false
}

// readSecretValue reads one key of a Secret as text.
func (i *Installer) readSecretValue(ctx context.Context, namespace, name, key string) (string, error) {
	data, err := i.readSecretKey(ctx, namespace, name, key)
	return string(data), err
}

// ---------------------------------------------------------------------------
// Day-to-day access
// ---------------------------------------------------------------------------

// openVault connects to the installed Vault as its administrator, through a
// port-forward. The returned func closes the connection.
func (i *Installer) openVault(ctx context.Context) (*vaultClient, func(), error) {
	token, err := i.readSecretValue(ctx, vaultNamespace, vaultKeysSecret, vaultRootTokenKey)
	if err != nil {
		return nil, nil, fmt.Errorf("vault is not set up (run `supplychain install`): %w", err)
	}
	base, stop, err := i.forwardToPod(ctx, vaultNamespace, vaultPod, vaultPort)
	if err != nil {
		return nil, nil, fmt.Errorf("reaching Vault: %w", err)
	}
	return &vaultClient{base: base, token: token, http: &http.Client{Timeout: 30 * time.Second}}, stop, nil
}

// SetSecret writes fields of one of the supply chain's secrets to Vault.
// A value that starts with "@" is read from the file named after it, which is
// how keys and other multi-line values are given.
func (i *Installer) SetSecret(ctx context.Context, group string, assignments []string) error {
	known, ok := store.Groups[group]
	if !ok {
		return fmt.Errorf("no secret %q; the secrets are: %s", group, strings.Join(secretGroups(), ", "))
	}
	fields, err := parseAssignments(assignments)
	if err != nil {
		return err
	}
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()
	if err := vault.write(ctx, store.Path(group), fields); err != nil {
		return err
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Printf("  ✓ %s/%s: set %s\n", store.Mount, store.Path(group), strings.Join(names, ", "))
	fmt.Printf("    (a working install needs: %s)\n", strings.Join(known, ", "))
	return nil
}

// ListSecrets prints which fields of each secret are set. It never prints a
// value.
func (i *Installer) ListSecrets(ctx context.Context) error {
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()
	for _, group := range secretGroups() {
		have, err := vault.read(ctx, store.Path(group))
		if err != nil {
			return err
		}
		fmt.Printf("%s/%s\n", store.Mount, store.Path(group))
		for _, field := range store.Groups[group] {
			state := "missing"
			if have[field] != "" {
				state = "set"
			}
			fmt.Printf("  %-16s %s\n", field, state)
			delete(have, field)
		}
		extra := make([]string, 0, len(have))
		for field := range have {
			extra = append(extra, field)
		}
		sort.Strings(extra)
		for _, field := range extra {
			fmt.Printf("  %-16s set (not used by the operator)\n", field)
		}
	}
	return nil
}

func secretGroups() []string {
	groups := make([]string, 0, len(store.Groups))
	for group := range store.Groups {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	return groups
}

// parseAssignments turns "field=value" and "field=@file" arguments into
// fields.
func parseAssignments(assignments []string) (map[string]string, error) {
	if len(assignments) == 0 {
		return nil, errors.New("nothing to set; give one or more field=value or field=@file")
	}
	fields := map[string]string{}
	for _, assignment := range assignments {
		name, value, ok := strings.Cut(assignment, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("%q is not field=value or field=@file", assignment)
		}
		if file, fromFile := strings.CutPrefix(value, "@"); fromFile {
			data, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("reading %s for field %s: %w", file, name, err)
			}
			value = string(data)
		}
		if value == "" {
			return nil, fmt.Errorf("field %s has no value", name)
		}
		fields[name] = value
	}
	return fields, nil
}
