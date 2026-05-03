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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ---------------------------------------------------------------------------
// SonarQube initialisation
// ---------------------------------------------------------------------------

// InitSonarQube bootstraps SonarQube after install:
//  1. Waits for SonarQube to be ready (up to 5 minutes)
//  2. Changes the default admin password to the provided one
//  3. Generates a user token named "supply-chain"
//  4. Patches the ClusterSecretStore fake provider with the token
//     at key /supplychain/sonarqube/token
//
// Called via: supplychain init-sonarqube --new-password <password>
func (i *Installer) InitSonarQube(ctx context.Context, newPassword string) error {
	const (
		sonarNamespace   = "default"
		sonarSvc         = "sonarqube-sonarqube"
		sonarPort        = "9000"
		sonarDefaultUser = "admin"
		sonarDefaultPass = "admin"
		tokenName        = "supply-chain"
		storeKey         = "/supplychain/sonarqube/token"
		storeName        = "secure-software-supply-chain-store"
		maxWait          = 5 * time.Minute
	)

	sonarURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:%s", sonarSvc, sonarNamespace, sonarPort)

	// ── 1. Wait for SonarQube to be ready ────────────────────────────────
	fmt.Println("  ⏳ Waiting for SonarQube to be ready...")
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		resp, err := httpGet(ctx, sonarURL+"/api/system/status")
		if err == nil && strings.Contains(resp, `"status":"UP"`) {
			break
		}
		fmt.Print(".")
		time.Sleep(5 * time.Second)
	}
	fmt.Println()

	// Verify it's actually up
	status, err := httpGet(ctx, sonarURL+"/api/system/status")
	if err != nil {
		return fmt.Errorf("SonarQube not reachable: %w", err)
	}
	if !strings.Contains(status, `"status":"UP"`) {
		return fmt.Errorf("SonarQube not ready after %s: %s", maxWait, status)
	}
	fmt.Println("  ✓ SonarQube is ready")

	// ── 2. Change default admin password ─────────────────────────────────
	fmt.Println("  🔐 Changing default admin password...")
	changePassURL := fmt.Sprintf("%s/api/users/change_password?login=admin&previousPassword=%s&password=%s",
		sonarURL, sonarDefaultPass, newPassword)
	if err := httpPost(ctx, changePassURL, sonarDefaultUser, sonarDefaultPass, ""); err != nil {
		// May already be changed — try with new password
		fmt.Println("  ℹ  Password may already be changed, continuing...")
	} else {
		fmt.Println("  ✓ Admin password changed")
	}

	// ── 3. Generate user token ────────────────────────────────────────────
	fmt.Printf("  🔑 Generating SonarQube token %q...\n", tokenName)

	// Revoke existing token first (idempotent)
	revokeURL := fmt.Sprintf("%s/api/user_tokens/revoke?name=%s", sonarURL, tokenName)
	_ = httpPost(ctx, revokeURL, sonarDefaultUser, newPassword, "")

	// Generate new token
	genURL := fmt.Sprintf("%s/api/user_tokens/generate?name=%s", sonarURL, tokenName)
	body, err := httpPostWithResponse(ctx, genURL, sonarDefaultUser, newPassword, "")
	if err != nil {
		return fmt.Errorf("generating SonarQube token: %w", err)
	}

	// Extract token value from response: {"login":"admin","name":"supply-chain","token":"squ_xxx","createdAt":"..."}
	token := extractJSONField(body, "token")
	if token == "" {
		return fmt.Errorf("could not extract token from SonarQube response: %s", body)
	}
	fmt.Printf("  ✓ Token generated: %s...\n", token[:min(8, len(token))])

	// ── 4. Patch ClusterSecretStore ───────────────────────────────────────
	fmt.Println("  📝 Patching ClusterSecretStore with SonarQube token...")
	if err := i.patchClusterSecretStoreToken(ctx, storeName, storeKey, token); err != nil {
		return fmt.Errorf("patching ClusterSecretStore: %w", err)
	}
	fmt.Println("  ✓ ClusterSecretStore updated")

	fmt.Println()
	fmt.Println("✅ SonarQube initialised successfully.")
	fmt.Printf("   Token stored at: %s\n", storeKey)
	fmt.Println()
	return nil
}

// patchClusterSecretStoreToken updates the fake provider entry for the given
// key in the ClusterSecretStore. Uses a JSON merge patch on the spec.
func (i *Installer) patchClusterSecretStoreToken(
	ctx context.Context,
	storeName, key, token string,
) error {
	storeGVR := schema.GroupVersionResource{
		Group:    "external-secrets.io",
		Version:  "v1",
		Resource: "clustersecretstores",
	}

	// Fetch current store.
	existing, err := i.dynamic.Resource(storeGVR).Get(ctx, storeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("fetching ClusterSecretStore: %w", err)
	}

	// Get current fake data array.
	fakeData, _, _ := unstructured.NestedSlice(existing.Object,
		"spec", "provider", "fake", "data")

	// Update or append the entry.
	updated := false
	for idx, entry := range fakeData {
		m, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if m["key"] == key {
			m["value"] = token
			fakeData[idx] = m
			updated = true
			break
		}
	}
	if !updated {
		fakeData = append(fakeData, map[string]interface{}{
			"key":   key,
			"value": token,
		})
	}

	// Write back.
	if err := unstructured.SetNestedSlice(existing.Object, fakeData,
		"spec", "provider", "fake", "data"); err != nil {
		return fmt.Errorf("setting fake data: %w", err)
	}

	_, err = i.dynamic.Resource(storeGVR).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// ---------------------------------------------------------------------------
// HTTP helpers (no external deps — stdlib only)
// ---------------------------------------------------------------------------

func httpGet(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func httpPost(ctx context.Context, url, user, pass, body string) error {
	_, err := httpPostWithResponse(ctx, url, user, pass, body)
	return err
}

func httpPostWithResponse(ctx context.Context, url, user, pass, body string) (string, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	if err != nil {
		return "", err
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return string(b), fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	return string(b), nil
}

// extractJSONField extracts a string field from a flat JSON object.
// Avoids importing encoding/json for a single use case.
func extractJSONField(body, field string) string {
	needle := fmt.Sprintf(`"%s":"`, field)
	idx := strings.Index(body, needle)
	if idx == -1 {
		return ""
	}
	start := idx + len(needle)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		return ""
	}
	return body[start : start+end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
