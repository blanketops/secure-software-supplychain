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

// The page is opened on a machine that may have no way out but to the
// cluster. It loads nothing from anywhere else, and reaches the cluster
// through the server that served it, whatever address that is.
func TestThePageIsSelfContained(t *testing.T) {
	external := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']https?://|@import|url\(\s*["']?https?://`)
	for _, file := range []string{"observer.html", "observer.css"} {
		data, err := static.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if found := external.FindString(string(data)); found != "" {
			t.Errorf("%s loads something from elsewhere: %s", file, found)
		}
		if strings.Contains(string(data), "localhost") || strings.Contains(string(data), "127.0.0.1") {
			t.Errorf("%s names an address; it has to work wherever it is served from", file)
		}
	}
	page, _ := static.ReadFile("observer.html")
	// What comes from the cluster or the log is written as text.
	if !strings.Contains(string(page), "const esc = ") {
		t.Error("the page has no escaping of what it shows")
	}
	// Everything is on the one page: each part of it is a section to jump to.
	for _, section := range []string{"chains", "webhooks", "builds", "trust", "log", "permissions", "admission", "secrets", "activity"} {
		if !strings.Contains(string(page), `<section id="`+section+`">`) || !strings.Contains(string(page), `href="#`+section+`"`) {
			t.Errorf("the page has no section %q, or no link to it", section)
		}
	}
	css, _ := static.ReadFile("observer.css")
	if !strings.Contains(string(css), "prefers-color-scheme: dark") {
		t.Error("the stylesheet has no dark colours")
	}
}
