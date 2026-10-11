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
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGitHub is a repository's webhooks. Like GitHub, it refuses a second
// webhook with a URL it already has.
type fakeGitHub struct {
	hooks   map[int64]webhookConfig
	nextID  int64
	updated []int64
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var in createWebhookRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		for _, hook := range f.hooks {
			if hook.URL == in.Config.URL {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
		}
		f.nextID++
		f.hooks[f.nextID] = in.Config
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(webhookResponse{ID: f.nextID})
	case http.MethodGet:
		type hook struct {
			ID     int64         `json:"id"`
			Config webhookConfig `json:"config"`
		}
		out := []hook{}
		for id, config := range f.hooks {
			config.Secret = "" // GitHub never returns it
			out = append(out, hook{ID: id, Config: config})
		}
		_ = json.NewEncoder(w).Encode(out)
	case http.MethodPatch:
		var in updateWebhookRequest
		_ = json.NewDecoder(r.Body).Decode(&in)
		for id := range f.hooks {
			if strings.HasSuffix(r.URL.Path, "/hooks/"+itoa(id)) {
				f.hooks[id] = in.Config
				f.updated = append(f.updated, id)
			}
		}
	}
}

func itoa(id int64) string {
	data, _ := json.Marshal(id)
	return string(data)
}

func clientFor(t *testing.T, fake *fakeGitHub, token string) *Client {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	client := NewClient(token)
	client.baseURL = server.URL
	return client
}

// A cluster that is rebuilt finds the webhook its predecessor registered. It
// takes that webhook over, with its own secret, instead of failing for good.
func TestCreateWebhookTakesOverOneWithTheSameURL(t *testing.T) {
	const url = "https://your-machine.your-tailnet.ts.net"
	fake := &fakeGitHub{nextID: 40, hooks: map[int64]webhookConfig{
		7:  {URL: "https://elsewhere.example"},
		12: {URL: url, Secret: "the old cluster's"},
	}}
	client := clientFor(t, fake, "token")

	id, err := client.CreateWebhook(context.Background(), "your-org/your-app", url, nil, "new secret", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if id != 12 || len(fake.hooks) != 2 {
		t.Errorf("got webhook %d among %d, want the existing webhook 12 and no new one", id, len(fake.hooks))
	}
	if got := fake.hooks[12].Secret; got != "new secret" {
		t.Errorf("the webhook still signs with %q", got)
	}
	if fake.hooks[7].URL != "https://elsewhere.example" || len(fake.updated) != 1 {
		t.Errorf("another webhook was changed: updated %v", fake.updated)
	}
}

func TestCreateWebhook(t *testing.T) {
	fake := &fakeGitHub{nextID: 40, hooks: map[int64]webhookConfig{}}
	id, err := clientFor(t, fake, "token").CreateWebhook(context.Background(),
		"your-org/your-app", "https://your-machine.your-tailnet.ts.net", nil, "secret", false, "")
	if err != nil || id != 41 {
		t.Fatalf("CreateWebhook = %d, %v", id, err)
	}

	_, err = clientFor(t, fake, "refused").CreateWebhook(context.Background(),
		"your-org/your-app", "https://other.example", nil, "secret", false, "")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a refused token returned %v, want GitHub's 401", err)
	}
}
