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
	"net/url"
	"testing"
)

// The observer is opened by names other than localhost (a Tailscale name, a
// LAN address), and kubectl proxy refuses any Host but its own, so the
// observer has to speak to it under the proxy's address.
func TestTheObserverReachesKubectlProxyWhateverNameItIsOpenedBy(t *testing.T) {
	var gotHost string
	kubectlProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer kubectlProxy.Close()
	target, _ := url.Parse(kubectlProxy.URL)

	r := httptest.NewRequest(http.MethodGet, "https://pop-os.example.ts.net:8002/api", nil)
	w := httptest.NewRecorder()
	newAPIProxy(target).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	if gotHost != target.Host {
		t.Errorf("kubectl proxy was asked for Host %q; it only accepts its own address %q", gotHost, target.Host)
	}
}
