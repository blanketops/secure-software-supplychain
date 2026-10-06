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
	"strings"
	"testing"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
)

// SonarQube on its embedded database in an emptyDir forgot its admin
// password, its tokens and every analysis whenever its pod restarted.
func TestSonarQubeKeepsItsState(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := manifests.Dependencies.ReadFile("dependencies/sonarqube/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	release, database := read("release.yaml"), read("postgresql.yaml")

	for _, want := range []string{
		"name: SONAR_JDBC_URL",
		"jdbc:postgresql://sonarqube-postgresql.default.svc.cluster.local:5432/sonarqube",
		"claimName: sonarqube-data",
	} {
		if !strings.Contains(release, want) {
			t.Errorf("SonarQube manifest does not contain %q", want)
		}
	}
	for _, want := range []string{
		"kind: PersistentVolumeClaim", "name: sonarqube-data", "volumeClaimTemplates:", "name: " + sonarDatabaseSTS,
	} {
		if !strings.Contains(database, want) {
			t.Errorf("database manifest does not contain %q", want)
		}
	}
	// The password comes from the Secret the installer generates; neither
	// file may carry one.
	for name, manifest := range map[string]string{"release.yaml": release, "postgresql.yaml": database} {
		if strings.Count(manifest, "PASSWORD") != strings.Count(manifest, "PASSWORD\n              valueFrom:") {
			t.Errorf("%s sets a password as a literal value", name)
		}
		if !strings.Contains(manifest, "name: "+sonarDatabaseSecret) {
			t.Errorf("%s does not read the password from Secret %s", name, sonarDatabaseSecret)
		}
	}
	if strings.Contains(release, "sonarqube-ui-test") {
		t.Error("the chart's test pod is applied as a workload")
	}
}

// fakeSonar is SonarQube's authentication as the bootstrap sees it.
type fakeSonar struct {
	adminPassword string
	token         string
	generated     int
}

func (f *fakeSonar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, password, _ := r.BasicAuth()
	authenticated := (user == sonarAdmin && password == f.adminPassword) ||
		(f.token != "" && user == f.token && password == "")
	_ = r.ParseForm()
	switch r.URL.Path {
	case sonarContext + "/api/system/status":
		_, _ = w.Write([]byte(`{"status":"UP"}`))
	case sonarContext + "/api/authentication/validate":
		_ = json.NewEncoder(w).Encode(map[string]bool{"valid": authenticated})
	case sonarContext + "/api/users/change_password":
		if !authenticated || r.PostForm.Get("previousPassword") != f.adminPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.adminPassword = r.PostForm.Get("password")
		w.WriteHeader(http.StatusNoContent)
	case sonarContext + "/api/user_tokens/revoke":
		if authenticated {
			f.token = ""
		}
		w.WriteHeader(http.StatusNoContent)
	case sonarContext + "/api/user_tokens/generate":
		if !authenticated {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.generated++
		f.token = "squ_generated"
		_ = json.NewEncoder(w).Encode(map[string]string{"name": r.PostForm.Get("name"), "token": f.token})
	default:
		http.NotFound(w, r)
	}
}

func TestSonarQubeBootstrap(t *testing.T) {
	// A password with characters that mean something in a URL.
	const password = "Super#Secret&2026 +x"
	fake := &fakeSonar{adminPassword: sonarDefaultPassword}
	server := httptest.NewServer(fake)
	defer server.Close()
	sonar := &sonarClient{base: server.URL + sonarContext, http: server.Client()}
	ctx := context.Background()

	if err := sonar.waitUntilUp(ctx, 0); err == nil {
		t.Error("waitUntilUp with no time to wait reported success without asking")
	}

	changed, err := sonar.ensureAdminPassword(ctx, password)
	if err != nil || !changed {
		t.Fatalf("first run: changed=%v err=%v, want the default password replaced", changed, err)
	}
	if fake.adminPassword != password {
		t.Errorf("admin password is %q, want it to arrive intact as %q", fake.adminPassword, password)
	}
	changed, err = sonar.ensureAdminPassword(ctx, password)
	if err != nil || changed {
		t.Errorf("second run: changed=%v err=%v, want nothing to do", changed, err)
	}
	if _, err := sonar.ensureAdminPassword(ctx, "some-other-password"); err == nil {
		t.Error("a password that is neither the default nor the current one was accepted")
	}

	token, err := sonar.newToken(ctx, password)
	if err != nil || token != "squ_generated" {
		t.Fatalf("newToken = %q, %v", token, err)
	}
	if !sonar.valid(ctx, token, "") {
		t.Error("the token just generated is not valid")
	}
	if sonar.valid(ctx, "squ_stale", "") {
		t.Error("a token SonarQube does not know was reported valid")
	}
}
