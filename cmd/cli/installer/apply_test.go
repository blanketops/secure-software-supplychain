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

package cli

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

// A running Tekton webhook rewrites its own webhook configuration, so an
// install over an existing Tekton can lose an update to it. The apply is made
// again on the newer object rather than failing the step.
func TestApplyObjectRetriesWhenTheObjectChangedUnderIt(t *testing.T) {
	gvk := schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	configMap := func(value string) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]any{"data": map[string]any{"key": value}}}
		obj.SetGroupVersionKind(gvk)
		obj.SetNamespace("default")
		obj.SetName("settings")
		return obj
	}

	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), configMap("old"))
	conflicts := 2
	client.PrependReactor("update", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
		if conflicts == 0 {
			return false, nil, nil
		}
		conflicts--
		return true, nil, apierrors.NewConflict(gvr.GroupResource(), "settings", nil)
	})
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(gvk, meta.RESTScopeNamespace)
	i := &Installer{dynamic: client, mapper: mapper}

	if err := i.applyObject(context.Background(), configMap("new")); err != nil {
		t.Fatalf("applyObject gave up on a conflict: %v", err)
	}
	got, err := client.Resource(gvr).Namespace("default").Get(context.Background(), "settings", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if value, _, _ := unstructured.NestedString(got.Object, "data", "key"); value != "new" || conflicts != 0 {
		t.Errorf("after %d conflicts left, the object holds %q, want \"new\"", conflicts, value)
	}
}

// A component that generates its own certificate ships an empty Secret for
// it, and fills it when it starts. A second install must not empty it again:
// Tekton's interceptors then serve nothing until they are restarted.
func TestApplyObjectLeavesAFilledPlaceholderSecret(t *testing.T) {
	gvk := schema.GroupVersionKind{Version: "v1", Kind: "Secret"}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	secret := func(data map[string]any) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]any{}}
		if data != nil {
			obj.Object["data"] = data
		}
		obj.SetGroupVersionKind(gvk)
		obj.SetNamespace("default")
		obj.SetName("certs")
		return obj
	}
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(gvk, meta.RESTScopeNamespace)
	read := func(client *dynamicfake.FakeDynamicClient) map[string]any {
		got, err := client.Resource(gvr).Namespace("default").Get(context.Background(), "certs", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		data, _, _ := unstructured.NestedMap(got.Object, "data")
		return data
	}

	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), secret(map[string]any{"server-key.pem": "a2V5"}))
	i := &Installer{dynamic: client, mapper: mapper}
	if err := i.applyObject(context.Background(), secret(nil)); err != nil {
		t.Fatal(err)
	}
	if len(read(client)) != 1 {
		t.Error("the empty placeholder replaced what the component had generated")
	}

	// A Secret the manifest gives a value for is still set to that value.
	if err := i.applyObject(context.Background(), secret(map[string]any{"token": "bmV3"})); err != nil {
		t.Fatal(err)
	}
	if data := read(client); data["token"] != "bmV3" || len(data) != 1 {
		t.Errorf("a Secret with a value in the manifest was not applied: %v", data)
	}
}
