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
package ui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The observer may be served beyond this machine, so the Kubernetes API behind
// it answers only the reads the page makes.
func TestTheObserverOnlyForwardsThePagesReads(t *testing.T) {
	forwarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	guard := readOnly(forwarded)

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api", http.StatusTeapot},
		{http.MethodGet, "/apis/supplychain.blanketops.dev/v1alpha1/supplychains", http.StatusTeapot},
		{http.MethodGet, "/apis/supplychain.blanketops.dev/v1alpha1/namespaces/default/imagebuilds", http.StatusTeapot},
		{http.MethodHead, "/apis/supplychain.blanketops.dev/v1alpha1/namespaces/default/supplychains", http.StatusTeapot},
		{http.MethodGet, "/apis/external-secrets.io/v1/clustersecretstores", http.StatusTeapot},
		{http.MethodGet, "/apis/external-secrets.io/v1/namespaces/default/externalsecrets", http.StatusTeapot},
		{http.MethodGet, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", http.StatusTeapot},
		{http.MethodGet, "/apis/rbac.authorization.k8s.io/v1/clusterroles", http.StatusTeapot},
		{http.MethodGet, "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles", http.StatusTeapot},
		{http.MethodGet, "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings", http.StatusTeapot},
		{http.MethodGet, "/api/v1/namespaces/default/events", http.StatusTeapot},
		{http.MethodGet, "/api/v1/namespaces/default/serviceaccounts", http.StatusTeapot},

		// Writes, even to paths the page reads.
		{http.MethodPost, "/apis/supplychain.blanketops.dev/v1alpha1/namespaces/default/supplychains", http.StatusMethodNotAllowed},
		{http.MethodPut, "/apis/supplychain.blanketops.dev/v1alpha1/namespaces/default/supplychains/app", http.StatusMethodNotAllowed},
		{http.MethodPatch, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/api/v1/namespaces/default/events", http.StatusMethodNotAllowed},

		// Reads the page never makes.
		{http.MethodGet, "/api/v1/secrets", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/default/secrets", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/default/secrets/supply-chain-git", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/default/serviceaccounts/runner/token", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/default/pods/p/exec", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/vault/services/vault:8200/proxy/v1/secret", http.StatusForbidden},
		{http.MethodGet, "/apis/apps/v1/deployments", http.StatusForbidden},
		{http.MethodGet, "/apis/external-secrets.io/v1/namespaces/default/externalsecrets/x/status", http.StatusForbidden},
		{http.MethodGet, "/apis/rbac.authorization.k8s.io/v1/../../../api/v1/secrets", http.StatusForbidden},
		{http.MethodGet, "/apis/supplychain.blanketops.dev/v1alpha1/../../../api/v1/secrets", http.StatusForbidden},
		{http.MethodGet, "/api/", http.StatusForbidden},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://observer.test/", nil)
		r.URL.Path = c.path // httptest would clean it; the server does not
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s %s: got %d, want %d", c.method, c.path, w.Code, c.want)
		}
	}
}

// Every Kubernetes path the page builds has to be one the guard forwards,
// or that part of the page goes blank when it is served.
func TestEveryPathThePageReadsIsForwarded(t *testing.T) {
	data, err := static.ReadFile("observer.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	consts := map[string]string{}
	for _, m := range regexp.MustCompile(`const (GROUP|RBAC) = '([^']+)'`).FindAllStringSubmatch(page, -1) {
		consts[m[1]] = m[2]
	}
	if len(consts) != 2 {
		t.Fatalf("expected the GROUP and RBAC constants in the page, found %v", consts)
	}
	expand := strings.NewReplacer(
		"${base}", consts["GROUP"]+"/namespaces/default",
		"${GROUP}", consts["GROUP"],
		"${RBAC}", consts["RBAC"],
		"${n}", "default",
	)
	calls := regexp.MustCompile("(?:list|get)\\(['`]([^'`]+)['`]").FindAllStringSubmatch(page, -1)
	checked := 0
	for _, c := range calls {
		p := expand.Replace(c[1])
		if !strings.HasPrefix(p, "/api") {
			continue // the page's own /sigstore routes
		}
		if strings.Contains(p, "${") {
			t.Errorf("cannot resolve %q; teach this test the new placeholder", c[1])
			continue
		}
		checked++
		matched := false
		for _, allowed := range readablePaths {
			if allowed.MatchString(p) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("the page reads %s, which the observer refuses", p)
		}
	}
	if checked < 10 {
		t.Errorf("found only %d Kubernetes reads in the page; the pattern no longer matches how it fetches", checked)
	}
}
