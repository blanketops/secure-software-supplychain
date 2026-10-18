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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// webhookTimeoutSeconds is the longest admission budget Kubernetes allows
// (the default is 10). Verifying an image against every policy fetches a
// registry token, the manifest, the signatures and attestations, and looks
// Chains' entries up in Rekor; on a lossy link that takes longer than 10s, and
// the API server then reports "failed calling webhook ... context deadline
// exceeded" instead of the decision. failurePolicy stays Fail, so a timeout
// still refuses the pod. policy-controller keeps the field when it reconciles
// its own configuration. The read cluster gets the same from
// gitops/policy/policy-controller/webhook-timeout.yaml.
const webhookTimeoutSeconds = 30

// longestAdmissionTimeout is the Mutate of the Policy Controller step: it
// gives policy-controller's admission webhooks webhookTimeoutSeconds.
func longestAdmissionTimeout(_ *Installer, obj *unstructured.Unstructured) bool {
	kind := obj.GetKind()
	if obj.GetName() != "policy.sigstore.dev" ||
		(kind != "ValidatingWebhookConfiguration" && kind != "MutatingWebhookConfiguration") {
		return true
	}
	webhooks, _, _ := unstructured.NestedSlice(obj.Object, "webhooks")
	for _, w := range webhooks {
		if hook, ok := w.(map[string]any); ok {
			hook["timeoutSeconds"] = int64(webhookTimeoutSeconds)
		}
	}
	_ = unstructured.SetNestedSlice(obj.Object, webhooks, "webhooks")
	return true
}
