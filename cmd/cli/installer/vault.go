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
	"net/http"
	"os"
	"path/filepath"
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

	// With a Vault outside the cluster, External Secrets logs in with a
	// ServiceAccount token that Vault checks against the cluster's public
	// keys. Vault then never has to reach the cluster. The token is made for
	// this audience and no other.
	vaultJWTAuthMount = "supply-chain"
	vaultJWTAudience  = "vault"

	// With SPIFFE identities, External Secrets logs in with a JWT-SVID that
	// SPIRE issues to the secrets ServiceAccount, and Vault checks it against
	// SPIRE's OIDC discovery endpoint. The bridge in
	// dependencies/vault/spiffe keeps the current JWT-SVID in this Secret.
	vaultSPIFFEAuthMount = "jwt"
	vaultSPIFFESecret    = "supply-chain-vault-jwt"
	vaultSPIFFESecretKey = "jwt"
	vaultSPIFFEBridge    = "supply-chain-svid"

	// Where the CLI finds an existing Vault and a token for it: the same
	// variables and file the vault CLI uses.
	vaultAddrEnv   = "VAULT_ADDR"
	vaultTokenEnv  = "VAULT_TOKEN"
	vaultTokenFile = ".vault-token"
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

// read returns the value of one of the store's keys, or "" when it is not
// set. A key that does not exist is not an error.
func (v *vaultClient) read(ctx context.Context, key string) (string, error) {
	var got struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	status, err := v.call(ctx, http.MethodGet, "/v1/"+store.Mount+"/data/"+key, nil, &got)
	if status == http.StatusNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return got.Data.Data[store.Field], nil
}

// write sets the value of one of the store's keys.
func (v *vaultClient) write(ctx context.Context, key, value string) error {
	body := map[string]any{"data": map[string]string{store.Field: value}}
	_, err := v.call(ctx, http.MethodPost, "/v1/"+store.Mount+"/data/"+key, body, nil)
	return err
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

// startVault brings the Vault the manifests started to the point of being
// open: initialised, with its keys stored, and unsealed. It can be run again:
// Vault is initialised once, and its keys are never replaced, because nothing
// else can open the storage they protect.
func (i *Installer) startVault(ctx context.Context) error {
	vault, stop, err := i.connectToVault(ctx)
	if err != nil {
		return err
	}
	defer stop()

	unsealKey, _, err := i.initialiseVault(ctx, vault)
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
	return i.waitForStatefulSet(ctx, vaultNamespace, vaultSTS, readyTimeout)
}

// ensureSecretStore gives External Secrets a way into Vault and nothing more
// than it needs there: a login for one ServiceAccount, a policy that can read
// the supply chain's secrets, and the ClusterSecretStore that uses them.
//
// The Vault is the one the installer runs, or, with --vault-addr, one that
// already exists. Nothing here is specific to a build, so it can be run again.
func (i *Installer) ensureSecretStore(ctx context.Context) error {
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()
	if err := ensureSecretEngine(ctx, vault); err != nil {
		return err
	}

	var desired *unstructured.Unstructured
	if i.spiffeLogin() {
		if err := configureSPIFFEAuth(ctx, vault, i.opts.TrustDomain); err != nil {
			return err
		}
		desired = spiffeSecretStore()
	} else if i.opts.VaultAddr == "" {
		if err := configureKubernetesAuth(ctx, vault); err != nil {
			return err
		}
		desired = secretStore()
	} else {
		issuer, keys, err := i.serviceAccountKeys(ctx)
		if err != nil {
			return fmt.Errorf("reading the cluster's ServiceAccount signing keys: %w", err)
		}
		if err := configureJWTAuth(ctx, vault, issuer, keys); err != nil {
			return err
		}
		desired = externalSecretStore(i.opts.VaultAddr)
	}
	if err := i.applyObject(ctx, desired); err != nil {
		if meta.IsNoMatchError(err) {
			return fmt.Errorf("the External Secrets Operator is not installed; install it, then run this step again: %w", err)
		}
		return fmt.Errorf("creating ClusterSecretStore %s: %w", store.Name, err)
	}
	return i.waitForSecretStore(ctx, 3*time.Minute)
}

// spiffeLogin reports whether the store logs in to Vault with a SPIFFE
// identity: when the stack has SPIRE, and Vault is the one in this cluster. A
// Vault somewhere else cannot reach SPIRE's discovery endpoint, which is only
// served inside the cluster, so it keeps checking ServiceAccount tokens.
func (i *Installer) spiffeLogin() bool {
	return i.spiffe() && i.opts.VaultAddr == "" && !i.opts.ExternalSecretStore
}

// secretsSPIFFEID is the identity SPIRE issues to the secrets ServiceAccount,
// and the only one Vault's role accepts.
func secretsSPIFFEID(trustDomain string) string {
	return "spiffe://" + trustDomain + "/ns/" + vaultNamespace + "/sa/" + vaultServiceAccount
}

// waitForSecretStore waits until External Secrets has logged in to Vault
// through the store. A store that exists but cannot log in would only show up
// later, as builds waiting for secrets that never arrive.
func (i *Installer) waitForSecretStore(ctx context.Context, timeout time.Duration) error {
	stores := i.dynamic.Resource(schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1", Resource: "clustersecretstores",
	})
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		obj, err := stores.Get(ctx, store.Name, metav1.GetOptions{})
		if err == nil {
			conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
			for _, raw := range conditions {
				condition, _ := raw.(map[string]any)
				if condition["type"] != "Ready" {
					continue
				}
				if condition["status"] == "True" {
					return nil
				}
				last = fmt.Sprintf("%v: %v", condition["reason"], condition["message"])
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("ClusterSecretStore %s could not log in to Vault within %s (%s)", store.Name, timeout, last)
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

// ensureSecretEngine makes sure the key-value engine the secrets live in is
// there, and that it is the kind the store expects.
func ensureSecretEngine(ctx context.Context, vault *vaultClient) error {
	// Vault answers with the mounts under "data", and repeats them beside
	// it among fields of its own; only "data" is read.
	var listed struct {
		Data map[string]struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		} `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/mounts", nil, &listed); err != nil {
		return fmt.Errorf("listing Vault's secret engines: %w", err)
	}
	if mount, ok := listed.Data[store.Mount+"/"]; ok {
		if mount.Type != "kv" || mount.Options["version"] != "2" {
			return fmt.Errorf("vault has %s/ mounted as %s version %q; the store needs a version 2 key-value engine there",
				store.Mount, mount.Type, mount.Options["version"])
		}
		return nil
	}
	engine := map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/sys/mounts/"+store.Mount, engine, nil); err != nil {
		return fmt.Errorf("enabling the key-value engine: %w", err)
	}
	return nil
}

// ensureAuthMethod enables an auth method at a mount, unless one of that type
// is already there. A mount of another type is someone else's, and is left.
func ensureAuthMethod(ctx context.Context, vault *vaultClient, mount, kind string) error {
	var listed struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/auth", nil, &listed); err != nil {
		return fmt.Errorf("listing Vault's auth methods: %w", err)
	}
	if existing, ok := listed.Data[mount+"/"]; ok {
		if existing.Type != kind {
			return fmt.Errorf("vault already has auth method %s/ of type %s; it is not replaced with %s",
				mount, existing.Type, kind)
		}
		return nil
	}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/sys/auth/"+mount, map[string]any{"type": kind}, nil); err != nil {
		return fmt.Errorf("enabling %s auth at %s/: %w", kind, mount, err)
	}
	return nil
}

func writeReadPolicy(ctx context.Context, vault *vaultClient) error {
	policy := map[string]any{"policy": vaultReadPolicy()}
	if _, err := vault.call(ctx, http.MethodPut, "/v1/sys/policies/acl/"+vaultPolicy, policy, nil); err != nil {
		return fmt.Errorf("writing policy %s: %w", vaultPolicy, err)
	}
	return nil
}

// configureKubernetesAuth is for the Vault that runs in this cluster: it
// checks a ServiceAccount token by asking the API server who it belongs to.
func configureKubernetesAuth(ctx context.Context, vault *vaultClient) error {
	if err := ensureAuthMethod(ctx, vault, vaultAuthMount, "kubernetes"); err != nil {
		return err
	}
	// Running in the cluster, Vault verifies tokens with its own
	// ServiceAccount and the cluster's CA; it only needs to be told where
	// the API server is.
	config := map[string]any{"kubernetes_host": "https://kubernetes.default.svc"}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/auth/"+vaultAuthMount+"/config", config, nil); err != nil {
		return fmt.Errorf("configuring Kubernetes auth: %w", err)
	}
	if err := writeReadPolicy(ctx, vault); err != nil {
		return err
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

// configureJWTAuth is for a Vault outside the cluster. It is given the
// cluster's public keys and checks ServiceAccount tokens against them itself,
// so it needs no route to the cluster and holds no credential for it. Only
// tokens from this cluster's issuer, made for Vault, for the one
// ServiceAccount, are accepted.
func configureJWTAuth(ctx context.Context, vault *vaultClient, issuer string, publicKeys []string) error {
	if err := ensureAuthMethod(ctx, vault, vaultJWTAuthMount, "jwt"); err != nil {
		return err
	}
	config := map[string]any{"jwt_validation_pubkeys": publicKeys, "bound_issuer": issuer}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/auth/"+vaultJWTAuthMount+"/config", config, nil); err != nil {
		return fmt.Errorf("configuring JWT auth: %w", err)
	}
	if err := writeReadPolicy(ctx, vault); err != nil {
		return err
	}
	role := map[string]any{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"bound_subject":   "system:serviceaccount:" + vaultNamespace + ":" + vaultServiceAccount,
		"bound_audiences": []string{vaultJWTAudience},
		"token_policies":  []string{vaultPolicy},
		"token_ttl":       "1h",
	}
	path := "/v1/auth/" + vaultJWTAuthMount + "/role/" + vaultRole
	if _, err := vault.call(ctx, http.MethodPost, path, role, nil); err != nil {
		return fmt.Errorf("writing role %s: %w", vaultRole, err)
	}
	return nil
}

// configureSPIFFEAuth makes a SPIFFE identity the way in to Vault, as in
// https://spiffe.io/docs/latest/keyless/vault/readme/. Vault trusts SPIRE's
// OIDC discovery endpoint, and gives a token only for a JWT-SVID that SPIRE
// signed, that was made for Vault, and whose subject is the secrets
// ServiceAccount's SPIFFE ID. The token lives as long as the JWT-SVID does.
//
// The Kubernetes login an earlier install may have set up is taken away, so
// that the SPIFFE identity is the only one that can read the secrets.
func configureSPIFFEAuth(ctx context.Context, vault *vaultClient, trustDomain string) error {
	if err := ensureAuthMethod(ctx, vault, vaultSPIFFEAuthMount, "jwt"); err != nil {
		return err
	}
	config := map[string]any{"oidc_discovery_url": spireOIDCIssuer, "bound_issuer": spireOIDCIssuer}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/auth/"+vaultSPIFFEAuthMount+"/config", config, nil); err != nil {
		return fmt.Errorf("pointing Vault at SPIRE's OIDC discovery at %s: %w", spireOIDCIssuer, err)
	}
	if err := writeReadPolicy(ctx, vault); err != nil {
		return err
	}
	role := map[string]any{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"bound_subject":   secretsSPIFFEID(trustDomain),
		"bound_audiences": []string{vaultJWTAudience},
		"token_policies":  []string{vaultPolicy},
		"token_ttl":       "10m",
	}
	path := "/v1/auth/" + vaultSPIFFEAuthMount + "/role/" + vaultRole
	if _, err := vault.call(ctx, http.MethodPost, path, role, nil); err != nil {
		return fmt.Errorf("writing role %s: %w", vaultRole, err)
	}
	return removeKubernetesLogin(ctx, vault)
}

// removeKubernetesLogin deletes the role that let the ServiceAccount log in
// with its Kubernetes token, if Kubernetes auth was ever enabled.
func removeKubernetesLogin(ctx context.Context, vault *vaultClient) error {
	var listed struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/auth", nil, &listed); err != nil {
		return fmt.Errorf("listing Vault's auth methods: %w", err)
	}
	if listed.Data[vaultAuthMount+"/"].Type != "kubernetes" {
		return nil
	}
	if _, err := vault.call(ctx, http.MethodDelete, "/v1/auth/"+vaultAuthMount+"/role/"+vaultRole, nil, nil); err != nil {
		return fmt.Errorf("removing the Kubernetes login: %w", err)
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

// externalSecretStore is the store for a Vault outside the cluster, at the
// address the cluster reaches it by. External Secrets asks the API server for
// a short-lived token for the ServiceAccount, made for Vault, and presents it.
func externalSecretStore(server string) *unstructured.Unstructured {
	obj := secretStore()
	_ = unstructured.SetNestedField(obj.Object, server, "spec", "provider", "vault", "server")
	_ = unstructured.SetNestedMap(obj.Object, map[string]any{
		"jwt": map[string]any{
			"path": vaultJWTAuthMount,
			"role": vaultRole,
			"kubernetesServiceAccountToken": map[string]any{
				"serviceAccountRef": map[string]any{
					"name":      vaultServiceAccount,
					"namespace": vaultNamespace,
				},
				"audiences":         []any{vaultJWTAudience},
				"expirationSeconds": int64(600),
			},
		},
	}, "spec", "provider", "vault", "auth")
	return obj
}

// spiffeSecretStore is the store when the login is a SPIFFE identity. External
// Secrets presents the JWT-SVID it finds in the Secret the bridge keeps
// current. It is valid for minutes, so the store still holds nothing lasting.
func spiffeSecretStore() *unstructured.Unstructured {
	obj := secretStore()
	_ = unstructured.SetNestedMap(obj.Object, map[string]any{
		"jwt": map[string]any{
			"path": vaultSPIFFEAuthMount,
			"role": vaultRole,
			"secretRef": map[string]any{
				"name":      vaultSPIFFESecret,
				"namespace": vaultNamespace,
				"key":       vaultSPIFFESecretKey,
			},
		},
	}, "spec", "provider", "vault", "auth")
	return obj
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

// openVault connects to Vault with rights to administer it. The returned
// func closes the connection.
//
// An existing Vault is used when VAULT_ADDR is set, or the install named one
// with --vault-addr; its token comes from VAULT_TOKEN or ~/.vault-token, as
// with the vault CLI. Otherwise it is the Vault the installer runs, reached
// through a port-forward, with the token the installer stored.
func (i *Installer) openVault(ctx context.Context) (*vaultClient, func(), error) {
	address := os.Getenv(vaultAddrEnv)
	if address == "" {
		address = i.opts.VaultAddr
	}
	if address != "" {
		token, err := existingVaultToken()
		if err != nil {
			return nil, nil, err
		}
		vault := &vaultClient{
			base:  strings.TrimRight(address, "/"),
			token: token,
			http:  &http.Client{Timeout: 30 * time.Second},
		}
		if _, err := vault.call(ctx, http.MethodGet, "/v1/auth/token/lookup-self", nil, nil); err != nil {
			return nil, nil, fmt.Errorf("logging in to Vault at %s: %w", address, err)
		}
		return vault, func() {}, nil
	}

	token, err := i.readSecretValue(ctx, vaultNamespace, vaultKeysSecret, vaultRootTokenKey)
	if err != nil {
		return nil, nil, fmt.Errorf("vault is not set up (run `supplychain install`, or set %s for a Vault of your own): %w",
			vaultAddrEnv, err)
	}
	base, stop, err := i.forwardToPod(ctx, vaultNamespace, vaultPod, vaultPort)
	if err != nil {
		return nil, nil, fmt.Errorf("reaching Vault: %w", err)
	}
	return &vaultClient{base: base, token: token, http: &http.Client{Timeout: 30 * time.Second}}, stop, nil
}

// existingVaultToken finds a token the way the vault CLI does.
func existingVaultToken() (string, error) {
	if token := strings.TrimSpace(os.Getenv(vaultTokenEnv)); token != "" {
		return token, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(home, vaultTokenFile))
	if err != nil {
		return "", fmt.Errorf("no Vault token: set %s or log in with `vault login` (%w)", vaultTokenEnv, err)
	}
	if token := strings.TrimSpace(string(data)); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("%s is empty", filepath.Join(home, vaultTokenFile))
}

// SetSecrets writes values to the store's keys in Vault. Each assignment is
// "key=value", or "key=@file" to read the value from a file, which is how
// keys and other multi-line values are given. A key may be given without the
// prefix they share: "git/ssh-privatekey".
func (i *Installer) SetSecrets(ctx context.Context, assignments []string) error {
	values, err := parseAssignments(assignments)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, entry := range store.Keys {
		known[entry.Key] = true
	}
	keys := make([]string, 0, len(values))
	for name := range values {
		if !known[store.Key(name)] {
			return fmt.Errorf("%q is not one of the store's keys; see `supplychain secrets list`", name)
		}
		keys = append(keys, name)
	}
	sort.Strings(keys)

	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()
	for _, name := range keys {
		if err := vault.write(ctx, store.Key(name), values[name]); err != nil {
			return err
		}
		fmt.Printf("  ✓ set %s/%s\n", store.Mount, store.Key(name))
	}
	return nil
}

// GetSecret prints the value Vault holds for one of the store's keys, as
// `vault kv get -field=value` would. Nothing else is written to standard
// output, so the value can be piped or compared.
func (i *Installer) GetSecret(ctx context.Context, name string) error {
	key := store.Key(name)
	known := false
	for _, entry := range store.Keys {
		known = known || entry.Key == key
	}
	if !known {
		return fmt.Errorf("%q is not one of the store's keys; see `supplychain secrets list`", name)
	}
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()
	value, err := vault.read(ctx, key)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("%s/%s is not set", store.Mount, key)
	}
	_, err = fmt.Fprint(os.Stdout, value)
	return err
}

// ListSecrets prints which of the store's keys are set. It never prints a
// value.
func (i *Installer) ListSecrets(ctx context.Context) error {
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()
	for _, entry := range store.Keys {
		value, err := vault.read(ctx, entry.Key)
		if err != nil {
			return err
		}
		state := "missing"
		if value != "" {
			state = "set"
		}
		fmt.Printf("  %-36s %-8s %s\n", entry.Key, state, entry.Purpose)
	}
	return nil
}

// parseAssignments turns "key=value" and "key=@file" arguments into values by
// key.
func parseAssignments(assignments []string) (map[string]string, error) {
	if len(assignments) == 0 {
		return nil, errors.New("nothing to set; give one or more key=value or key=@file")
	}
	fields := map[string]string{}
	for _, assignment := range assignments {
		name, value, ok := strings.Cut(assignment, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("%q is not key=value or key=@file", assignment)
		}
		if file, fromFile := strings.CutPrefix(value, "@"); fromFile {
			data, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("reading %s for %s: %w", file, name, err)
			}
			value = string(data)
		}
		if value == "" {
			return nil, fmt.Errorf("%s has no value", name)
		}
		fields[name] = value
	}
	return fields, nil
}
