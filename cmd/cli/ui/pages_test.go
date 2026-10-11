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
	"regexp"
	"strings"
	"testing"
)

// The pages are opened on a machine that may have no way out but to the
// cluster. They load nothing from anywhere else, share one stylesheet, and
// reach the cluster through the server that served them, whatever address
// that is.
func TestPagesAreSelfContained(t *testing.T) {
	external := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']https?://|@import|url\(\s*["']?https?://`)
	for _, page := range []string{"supply_chain.html", "rbac.html"} {
		data, err := static.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if found := external.FindString(text); found != "" {
			t.Errorf("%s loads something from elsewhere: %s", page, found)
		}
		if !strings.Contains(text, `<link rel="stylesheet" href="/observer.css">`) {
			t.Errorf("%s does not use the shared stylesheet", page)
		}
		if strings.Contains(text, "localhost") || strings.Contains(text, "127.0.0.1") {
			t.Errorf("%s names an address; it has to work wherever it is served from", page)
		}
		for _, link := range []string{`href="/overview"`, `href="/permissions"`} {
			if !strings.Contains(text, link) {
				t.Errorf("%s does not link to %s", page, link)
			}
		}
		// What comes from the cluster or the log is written as text.
		if !strings.Contains(text, "const esc = ") {
			t.Errorf("%s has no escaping of what it shows", page)
		}
	}
	css, err := static.ReadFile("observer.css")
	if err != nil {
		t.Fatal(err)
	}
	if found := external.FindString(string(css)); found != "" {
		t.Errorf("the stylesheet loads something from elsewhere: %s", found)
	}
	if !strings.Contains(string(css), "prefers-color-scheme: dark") {
		t.Error("the stylesheet has no dark colours")
	}
}
