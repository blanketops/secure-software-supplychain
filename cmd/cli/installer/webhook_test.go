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
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The admission webhooks get the longest budget Kubernetes allows: verifying
// an image against every policy fetches from the registry and Rekor, and past
// the default 10s the API server reports a timeout instead of the decision.
// Nothing else in the release is changed.
func TestPolicyControllerWebhooksGetTheLongestTimeout(t *testing.T) {
	var mutate func(*Installer, *unstructured.Unstructured) bool
	for _, s := range installOrder {
		if s.Name == "Policy Controller" {
			mutate = s.Mutate
		}
	}
	if mutate == nil {
		t.Fatal("the Policy Controller step has no Mutate")
	}

	found := 0
	for _, obj := range manifestObjects(t, "dependencies/sigstore/policy-controller/release.yaml") {
		before := obj.DeepCopy()
		if !mutate(&Installer{}, obj) {
			t.Errorf("%s %s is no longer applied", obj.GetKind(), obj.GetName())
		}
		admission := obj.GetName() == "policy.sigstore.dev" &&
			(obj.GetKind() == "ValidatingWebhookConfiguration" || obj.GetKind() == "MutatingWebhookConfiguration")
		if !admission {
			if !reflect.DeepEqual(before.Object, obj.Object) {
				t.Errorf("%s %s was changed", obj.GetKind(), obj.GetName())
			}
			continue
		}
		found++
		webhooks, _, _ := unstructured.NestedSlice(obj.Object, "webhooks")
		for _, w := range webhooks {
			if got := w.(map[string]any)["timeoutSeconds"]; got != int64(webhookTimeoutSeconds) || webhookTimeoutSeconds != 30 {
				t.Errorf("%s %s: timeoutSeconds = %v; want 30", obj.GetKind(), obj.GetName(), got)
			}
		}
	}
	if found != 2 {
		t.Fatalf("found %d policy.sigstore.dev webhook configurations; want the validating and the mutating one", found)
	}
}
