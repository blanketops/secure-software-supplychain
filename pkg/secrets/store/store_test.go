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

// Vault's policy lets the store read below Prefix only. A key placed anywhere
// else would simply not be readable, so every key has to be there.
func TestEveryKeyIsUnderThePrefix(t *testing.T) {
	seen := map[string]bool{}
	for _, entry := range Keys {
		if !strings.HasPrefix(entry.Key, Prefix+"/") {
			t.Errorf("key %q is outside %s/", entry.Key, Prefix)
		}
		if seen[entry.Key] || entry.Purpose == "" {
			t.Errorf("key %q is listed twice or has no purpose", entry.Key)
		}
		seen[entry.Key] = true
	}
	for _, key := range []string{GitPrivateKey, GitKnownHosts, GitSSHConfig, RegistryConfig, GitHubToken, SonarQubeToken} {
		if !seen[key] {
			t.Errorf("%s is not in Keys, so the CLI cannot set or list it", key)
		}
	}
}

// The CLI takes keys with or without the prefix they all share.
func TestKey(t *testing.T) {
	for given, want := range map[string]string{
		"git/ssh-privatekey":             GitPrivateKey,
		"supplychain/git/ssh-privatekey": GitPrivateKey,
		"registry/config":                RegistryConfig,
	} {
		if got := Key(given); got != want {
			t.Errorf("Key(%q) = %q, want %q", given, got, want)
		}
	}
}

func TestRemoteRefNamesAKeyAndItsField(t *testing.T) {
	ref := RemoteRef(GitPrivateKey)
	if ref["key"] != "supplychain/git/ssh-privatekey" || ref["property"] != "value" {
		t.Errorf("remoteRef = %v", ref)
	}
	if got := Ref(); got["name"] != Name || got["kind"] != Kind {
		t.Errorf("secretStoreRef = %v", got)
	}
}
