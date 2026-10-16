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
	"path"
	"regexp"
)

// readablePaths are the Kubernetes API paths the page reads, and the only ones
// the observer forwards. kubectl proxy holds the caller's credentials, often
// cluster-admin, so forwarding everything would hand any viewer of the page
// the cluster: Secrets, exec, service proxies and every write.
var readablePaths = []*regexp.Regexp{
	regexp.MustCompile(`^/api$`),
	regexp.MustCompile(`^/apis/supplychain\.blanketops\.dev/v1alpha1(/.*)?$`),
	regexp.MustCompile(`^/apis/external-secrets\.io/v1/(clustersecretstores|namespaces/[^/]+/externalsecrets)$`),
	regexp.MustCompile(`^/apis/rbac\.authorization\.k8s\.io/v1/(clusterroles|clusterrolebindings|namespaces/[^/]+/(roles|rolebindings))$`),
	regexp.MustCompile(`^/api/v1/namespaces/[^/]+/(events|serviceaccounts)$`),
}

// readOnly forwards GET and HEAD requests for readablePaths to next and
// refuses everything else.
func readOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "the observer only reads", http.StatusMethodNotAllowed)
			return
		}
		// Match on the cleaned path, so /apis/rbac.../../../api/v1/secrets
		// cannot ride on an allowed prefix.
		p := path.Clean(r.URL.Path)
		if p != r.URL.Path {
			http.Error(w, "not a path the observer reads", http.StatusForbidden)
			return
		}
		for _, allowed := range readablePaths {
			if allowed.MatchString(p) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "not a path the observer reads", http.StatusForbidden)
	})
}
