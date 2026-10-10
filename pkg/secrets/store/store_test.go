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

package store

import (
	"strings"
	"testing"
)

// Vault's policy lets the store read below Prefix only. A secret placed
// anywhere else would simply not be readable, so every path has to be there.
func TestEverySecretIsUnderThePrefix(t *testing.T) {
	for group := range Groups {
		if path := Path(group); !strings.HasPrefix(path, Prefix+"/") || strings.HasPrefix(path, "/") {
			t.Errorf("secret %s is at %q, outside %s/", group, path, Prefix)
		}
	}
	for _, path := range []string{Git, Registry, GitHub, SonarQube} {
		if Groups[strings.TrimPrefix(path, Prefix+"/")] == nil {
			t.Errorf("%s is not one of the CLI's secrets", path)
		}
	}
}

func TestRemoteRefNamesASecretAndAField(t *testing.T) {
	ref := RemoteRef(Git, GitPrivateKey)
	if ref["key"] != "supplychain/git" || ref["property"] != "ssh-privatekey" {
		t.Errorf("remoteRef = %v", ref)
	}
	if got := Ref(); got["name"] != Name || got["kind"] != Kind {
		t.Errorf("secretStoreRef = %v", got)
	}
}
