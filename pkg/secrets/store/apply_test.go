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
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func externalSecret(key string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "external-secrets.io/v1",
		"kind":       "ExternalSecret",
		"metadata":   map[string]any{"name": "git", "namespace": "default"},
		"spec": map[string]any{
			"refreshInterval": RefreshInterval,
			"secretStoreRef":  Ref(),
			"data": []any{
				map[string]any{"secretKey": "id_rsa", "remoteRef": RemoteRef(key, GitPrivateKey)},
			},
		},
	}}
}

// The operator owns its ExternalSecrets: one edited to read from somewhere
// else is put back. The defaults External Secrets adds to a spec are not a
// difference.
func TestApply(t *testing.T) {
	scheme := runtime.NewScheme()
	gvk := schema.GroupVersionKind{Group: "external-secrets.io", Version: "v1", Kind: "ExternalSecret"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(gvk.GroupVersion().WithKind("ExternalSecretList"), &unstructured.UnstructuredList{})
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	read := func() *unstructured.Unstructured {
		t.Helper()
		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(gvk)
		if err := c.Get(ctx, client.ObjectKey{Namespace: "default", Name: "git"}, got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	key := func(obj *unstructured.Unstructured) any {
		data, _, _ := unstructured.NestedSlice(obj.Object, "spec", "data")
		return data[0].(map[string]any)["remoteRef"].(map[string]any)["key"]
	}

	if outcome, err := Apply(ctx, c, externalSecret(Git)); err != nil || outcome != Created {
		t.Fatalf("first apply: %s, %v; want created", outcome, err)
	}

	// What External Secrets adds on its own must not look like drift.
	live := read()
	_ = unstructured.SetNestedField(live.Object, "Owner", "spec", "target", "creationPolicy")
	if err := c.Update(ctx, live); err != nil {
		t.Fatal(err)
	}
	if outcome, err := Apply(ctx, c, externalSecret(Git)); err != nil || outcome != Unchanged {
		t.Errorf("apply over a defaulted object: %s, %v; want unchanged", outcome, err)
	}

	// A hand edit that points it at another secret.
	live = read()
	data, _, _ := unstructured.NestedSlice(live.Object, "spec", "data")
	data[0].(map[string]any)["remoteRef"] = map[string]any{"key": "somewhere/else", "property": "key"}
	_ = unstructured.SetNestedSlice(live.Object, data, "spec", "data")
	if err := c.Update(ctx, live); err != nil {
		t.Fatal(err)
	}
	if outcome, err := Apply(ctx, c, externalSecret(Git)); err != nil || outcome != Updated {
		t.Errorf("apply over a changed object: %s, %v; want updated", outcome, err)
	}
	if got := key(read()); got != Git {
		t.Errorf("after apply the ExternalSecret reads %v, want %s", got, Git)
	}
}
