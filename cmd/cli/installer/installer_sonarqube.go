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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/store"
)

const (
	sonarNamespace = "default"
	sonarPod       = "sonarqube-sonarqube-0"
	sonarPort      = 9000
	// sonarContext is the path SonarQube is served under (SONAR_WEB_CONTEXT).
	sonarContext = "/sonarqube"

	sonarAdmin           = "admin"
	sonarDefaultPassword = "admin"
	sonarTokenName       = "supply-chain"

	sonarDatabaseSecret = "sonarqube-postgresql"
	sonarDatabaseSTS    = "sonarqube-postgresql"
	sonarSTS            = "sonarqube-sonarqube"
)

var (
	secretGVR         = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	externalSecretGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1", Resource: "externalsecrets",
	}
)

// ---------------------------------------------------------------------------
// SonarQube database
// ---------------------------------------------------------------------------

// ensureSonarQubeDatabasePassword creates the password SonarQube and its
// PostgreSQL share. It is generated once and never replaced: PostgreSQL only
// reads it when it initialises an empty data directory, so a new password
// would lock SonarQube out of the database it already has.
func (i *Installer) ensureSonarQubeDatabasePassword(ctx context.Context) error {
	secrets := i.dynamic.Resource(secretGVR).Namespace(sonarNamespace)
	_, err := secrets.Get(ctx, sonarDatabaseSecret, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("reading secret %s/%s: %w", sonarNamespace, sonarDatabaseSecret, err)
	}

	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generating the SonarQube database password: %w", err)
	}
	secret := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      sonarDatabaseSecret,
			"namespace": sonarNamespace,
			"labels":    map[string]any{"blanketops.dev/managed": "true"},
		},
		"type":       "Opaque",
		"stringData": map[string]any{"password": hex.EncodeToString(random)},
	}}
	if _, err := secrets.Create(ctx, secret, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating secret %s/%s: %w", sonarNamespace, sonarDatabaseSecret, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// SonarQube initialisation
// ---------------------------------------------------------------------------

// InitSonarQube bootstraps SonarQube after install. It can be run again at
// any time; it only changes what is not already as it should be:
//
//  1. Waits for SonarQube to be up.
//  2. Sets the admin password, if it is still the default.
//  3. Makes sure Vault holds a token SonarQube accepts,
//     generating one only when the stored one is missing or no longer valid.
//
// SonarQube is reached through a port-forward to its pod, so this works from
// wherever the kubeconfig does.
//
// Called via: supplychain init-sonarqube --new-password <password>
func (i *Installer) InitSonarQube(ctx context.Context, newPassword, tokenFile string) error {
	fmt.Println("  ⏳ Waiting for SonarQube to be ready...")
	if err := i.waitForStatefulSet(ctx, sonarNamespace, sonarSTS, readyTimeout); err != nil {
		return fmt.Errorf("SonarQube is not running: %w", err)
	}
	base, stop, err := i.forwardToSonarQube(ctx)
	if err != nil {
		return fmt.Errorf("reaching SonarQube: %w", err)
	}
	defer stop()
	sonar := &sonarClient{base: base, http: &http.Client{Timeout: 30 * time.Second}}

	if err := sonar.waitUntilUp(ctx, 5*time.Minute); err != nil {
		return err
	}
	fmt.Println("  ✓ SonarQube is ready")

	// ── Admin password ────────────────────────────────────────────────────
	changed, err := sonar.ensureAdminPassword(ctx, newPassword)
	if err != nil {
		return err
	}
	if changed {
		fmt.Println("  ✓ Admin password changed")
	} else {
		fmt.Println("  ✓ Admin password already set")
	}

	// ── Token ─────────────────────────────────────────────────────────────
	tokens, closeTokens, err := i.sonarTokenStore(ctx, tokenFile)
	if err != nil {
		return err
	}
	defer closeTokens()
	stored, err := tokens.get(ctx)
	if err != nil {
		return err
	}
	if stored != "" && sonar.valid(ctx, stored, "") {
		// Generating a new one would revoke this one, and every build that
		// already synced it would be refused until its Secret caught up.
		fmt.Printf("  ✓ The token in %s is valid; left as it is\n", tokens.where)
	} else {
		token, err := sonar.newToken(ctx, newPassword)
		if err != nil {
			return err
		}
		if err := tokens.put(ctx, token); err != nil {
			return fmt.Errorf("storing the SonarQube token in %s: %w", tokens.where, err)
		}
		fmt.Printf("  ✓ New token stored in %s\n", tokens.where)
	}

	refreshed, err := i.refreshSonarQubeTokenSecrets(ctx)
	if err != nil {
		return err
	}
	if refreshed > 0 {
		fmt.Printf("  ✓ Refreshed %d synced token Secret(s)\n", refreshed)
	}

	fmt.Println()
	fmt.Println("✅ SonarQube initialised.")
	fmt.Println()
	return nil
}

// forwardToSonarQube opens a port-forward to the SonarQube pod and returns
// the URL it is reachable at, context path included, and a func to close it.
func (i *Installer) forwardToSonarQube(ctx context.Context) (string, func(), error) {
	base, stop, err := i.forwardToPod(ctx, sonarNamespace, sonarPod, sonarPort)
	if err != nil {
		return "", nil, err
	}
	return base + sonarContext, stop, nil
}

// sonarTokens is where the SonarQube token is kept: Vault, or a file when the
// credentials are served by a store the installer does not run.
type sonarTokens struct {
	where string
	get   func(context.Context) (string, error)
	put   func(context.Context, string) error
}

func (i *Installer) sonarTokenStore(ctx context.Context, tokenFile string) (*sonarTokens, func(), error) {
	if tokenFile != "" {
		return &sonarTokens{
			where: tokenFile,
			get: func(context.Context) (string, error) {
				data, err := os.ReadFile(tokenFile)
				if os.IsNotExist(err) {
					return "", nil
				}
				return strings.TrimSpace(string(data)), err
			},
			put: func(_ context.Context, token string) error {
				return os.WriteFile(tokenFile, []byte(token+"\n"), 0o600)
			},
		}, func() {}, nil
	}
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w; with a secret store of your own, pass --token-file", err)
	}
	return &sonarTokens{
		where: "Vault at " + store.Mount + "/" + store.SonarQube,
		get: func(ctx context.Context) (string, error) {
			fields, err := vault.read(ctx, store.SonarQube)
			return fields[store.SonarQubeToken], err
		},
		put: func(ctx context.Context, token string) error {
			return vault.write(ctx, store.SonarQube, map[string]string{store.SonarQubeToken: token})
		},
	}, closeVault, nil
}

// refreshSonarQubeTokenSecrets makes External Secrets sync the token again
// into every Secret that carries it, and returns how many it touched.
//
// The operator creates those ExternalSecrets to sync once and never again.
// One that synced a token since replaced would keep handing builds the old
// one. Changing an ExternalSecret makes the operator sync it now, and giving
// it a refresh interval keeps it current from here on.
func (i *Installer) refreshSonarQubeTokenSecrets(ctx context.Context) (int, error) {
	list, err := i.dynamic.Resource(externalSecretGVR).List(ctx, metav1.ListOptions{
		LabelSelector: "blanketops.dev/purpose=sonarqube",
	})
	if err != nil {
		return 0, fmt.Errorf("listing ExternalSecrets: %w", err)
	}
	patch := fmt.Appendf(nil,
		`{"metadata":{"annotations":{"blanketops.dev/token-refreshed":%q}},"spec":{"refreshInterval":%q}}`,
		time.Now().UTC().Format(time.RFC3339), sonarTokenRefreshInterval)
	for idx := range list.Items {
		item := &list.Items[idx]
		_, err := i.dynamic.Resource(externalSecretGVR).Namespace(item.GetNamespace()).
			Patch(ctx, item.GetName(), types.MergePatchType, patch, metav1.PatchOptions{})
		if err != nil {
			return idx, fmt.Errorf("refreshing ExternalSecret %s/%s: %w", item.GetNamespace(), item.GetName(), err)
		}
	}
	return len(list.Items), nil
}

// sonarTokenRefreshInterval is how often a synced token Secret is brought up
// to date with the store.
const sonarTokenRefreshInterval = "1m"

// ---------------------------------------------------------------------------
// SonarQube API
// ---------------------------------------------------------------------------

// sonarClient is the little of SonarQube's web API the bootstrap needs.
type sonarClient struct {
	base string
	http *http.Client
}

func (s *sonarClient) waitUntilUp(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		_, body, err := s.call(ctx, http.MethodGet, "/api/system/status", "", "", nil)
		if err == nil && strings.Contains(body, `"status":"UP"`) {
			return nil
		}
		last = body
		if err != nil {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("SonarQube not up after %s: %.200s", timeout, last)
}

// valid reports whether SonarQube accepts the credentials. A token is passed
// as the user with an empty password.
func (s *sonarClient) valid(ctx context.Context, user, password string) bool {
	status, body, err := s.call(ctx, http.MethodGet, "/api/authentication/validate", user, password, nil)
	return err == nil && status == http.StatusOK && strings.Contains(body, `"valid":true`)
}

// ensureAdminPassword sets the admin password if it is still the default, and
// reports whether it changed it. A password that is neither the default nor
// the one given is an error: nothing here can sign in.
func (s *sonarClient) ensureAdminPassword(ctx context.Context, password string) (bool, error) {
	if s.valid(ctx, sonarAdmin, password) {
		return false, nil
	}
	if !s.valid(ctx, sonarAdmin, sonarDefaultPassword) {
		return false, errors.New("the SonarQube admin password is neither the default nor the one given")
	}
	status, body, err := s.call(ctx, http.MethodPost, "/api/users/change_password", sonarAdmin, sonarDefaultPassword,
		url.Values{"login": {sonarAdmin}, "previousPassword": {sonarDefaultPassword}, "password": {password}})
	if err != nil {
		return false, fmt.Errorf("changing the SonarQube admin password: %w", err)
	}
	if status >= 300 {
		return false, fmt.Errorf("changing the SonarQube admin password: HTTP %d: %.200s", status, body)
	}
	return true, nil
}

// newToken replaces the supply-chain token and returns the new one.
func (s *sonarClient) newToken(ctx context.Context, password string) (string, error) {
	name := url.Values{"name": {sonarTokenName}}
	// A token of that name may exist; its value cannot be read back.
	_, _, _ = s.call(ctx, http.MethodPost, "/api/user_tokens/revoke", sonarAdmin, password, name)
	status, body, err := s.call(ctx, http.MethodPost, "/api/user_tokens/generate", sonarAdmin, password, name)
	if err != nil {
		return "", fmt.Errorf("generating the SonarQube token: %w", err)
	}
	var generated struct {
		Token string `json:"token"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &generated) != nil || generated.Token == "" {
		return "", fmt.Errorf("generating the SonarQube token: HTTP %d: %.200s", status, body)
	}
	return generated.Token, nil
}

// call makes one request. Parameters go in the body, form-encoded, so that a
// password with characters that mean something in a URL arrives intact.
func (s *sonarClient) call(
	ctx context.Context,
	method, path, user, password string,
	form url.Values,
) (int, string, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, body)
	if err != nil {
		return 0, "", err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(data), err
}
