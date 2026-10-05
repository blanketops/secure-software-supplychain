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

package evidence

import (
	"encoding/base64"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// Docker Hub is written several ways; a credential stored under one of them
// has to be found for an image named with another.
func TestDockerConfigKeychain(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("user:secret"))
	keychain, err := newDockerConfigKeychain([]byte(`{"auths":{
		"https://index.docker.io/v1/": {"auth": "` + auth + `"},
		"registry.example:5000": {"username": "robot", "password": "token"}
	}}`))
	if err != nil {
		t.Fatal(err)
	}

	for image, want := range map[string]string{
		"docker.io/org/app:v1":        "user",
		"org/app":                     "user",
		"registry.example:5000/org/a": "robot",
		"ghcr.io/org/app":             "",
	} {
		ref, err := name.ParseReference(image)
		if err != nil {
			t.Fatal(err)
		}
		authenticator, err := keychain.Resolve(ref.Context())
		if err != nil {
			t.Fatal(err)
		}
		if want == "" {
			if authenticator != authn.Anonymous {
				t.Errorf("%s: got credentials, want anonymous", image)
			}
			continue
		}
		config, err := authenticator.Authorization()
		if err != nil {
			t.Fatal(err)
		}
		if config.Username != want {
			t.Errorf("%s: username %q, want %q", image, config.Username, want)
		}
	}

	if _, err := newDockerConfigKeychain([]byte("not json")); err == nil {
		t.Error("a malformed Docker config was accepted")
	}
}
