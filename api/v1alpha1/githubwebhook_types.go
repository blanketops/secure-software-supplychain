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
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GitHubWebhookSpec defines the desired state of GitHubWebhook.
//
// A GitHubWebhook CR registers a webhook on a GitHub repository that
// forwards push events to the supply chain EventListener. The controller
// waits for the referenced SupplyChain to be Ready before calling the
// GitHub API — ensuring the EventListener is up before events arrive.
type GitHubWebhookSpec struct {
	// Repository is the GitHub repository in "owner/repo" format.
	// The webhook will be registered on this repository.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`
	Repository string `json:"repository"`

	// SupplyChainRef references the SupplyChain that owns the EventListener
	// this webhook targets. The controller uses this as a readiness gate —
	// it will not register the webhook until the SupplyChain is Ready.
	// +kubebuilder:validation:Required
	SupplyChainRef LocalObjectRef `json:"supplyChainRef"`

	// HookURL is the publicly reachable URL where GitHub will deliver
	// webhook payloads. For local kind clusters use a smee.io channel URL.
	// For production clusters use the EventListener ingress URL.
	//
	// Examples:
	//   https://smee.io/XuueXgpAIZDpcz3f         (local dev)
	//   https://hooks.example.com/supply-chain    (production)
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https?://`
	HookURL string `json:"hookURL"`

	// Events is the list of GitHub event types to subscribe to.
	// Defaults to ["push"] if not specified.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:default={"push"}
	// +optional
	Events []string `json:"events,omitempty"`

	// ContentType is the webhook payload format.
	// Must be "json" or "form". Defaults to "json".
	// +kubebuilder:validation:Enum=json;form
	// +kubebuilder:default=json
	// +optional
	ContentType string `json:"contentType,omitempty"`

	// InsecureSSL controls whether GitHub verifies the SSL certificate
	// of the HookURL. Set to true only for development environments.
	// +kubebuilder:default=false
	// +optional
	InsecureSSL bool `json:"insecureSSL,omitempty"`

	// SecretRef references a Kubernetes Secret containing the GitHub
	// token used to call the GitHub API. The Secret must have a key
	// named "token" containing a GitHub personal access token or
	// GitHub App installation token with repo:write and admin:repo_hook
	// permissions.
	// +kubebuilder:validation:Required
	SecretRef LocalObjectRef `json:"secretRef"`

	// WebhookSecretRef optionally references a Kubernetes Secret containing
	// a shared secret used to sign GitHub webhook payloads. The Secret must
	// have a key named "secret". When set, the EventListener can verify
	// that payloads originate from GitHub.
	// +optional
	WebhookSecretRef *LocalObjectRef `json:"webhookSecretRef,omitempty"`
}

// GitHubWebhookStatus defines the observed state of GitHubWebhook.
type GitHubWebhookStatus struct {
	// Conditions represent the current state of the GitHubWebhook resource.
	//
	// Standard condition types:
	//   - "Ready":       the webhook is registered and receiving events
	//   - "Progressing": the webhook is being created or updated
	//   - "Degraded":    the webhook failed to register or was rejected by GitHub
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Phase is the overall webhook registration phase.
	// +kubebuilder:validation:Enum=Pending;Registering;Ready;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// WebhookID is the GitHub-assigned webhook ID. Stored so the controller
	// can update or delete the webhook without re-creating it.
	// +optional
	WebhookID int64 `json:"webhookID,omitempty"`

	// HookURL is the URL that was registered with GitHub. Stored to detect
	// changes that require a webhook update.
	// +optional
	HookURL string `json:"hookURL,omitempty"`

	// Repository is the GitHub repository the webhook was registered on.
	// +optional
	Repository string `json:"repository,omitempty"`

	// LastRegisteredAt is the timestamp of the last successful webhook
	// registration or update.
	// +optional
	LastRegisteredAt *metav1.Time `json:"lastRegisteredAt,omitempty"`

	// ObservedGeneration is the generation of the spec that was last
	// successfully reconciled. Used to detect spec changes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ghwh
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repository`
// +kubebuilder:printcolumn:name="HookURL",type=string,JSONPath=`.spec.hookURL`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="WebhookID",type=integer,JSONPath=`.status.webhookID`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// GitHubWebhook is the Schema for the githubwebhooks API.
// It registers a GitHub webhook that forwards push events to the
// supply chain EventListener, triggering automated ImageBuild executions.
type GitHubWebhook struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec GitHubWebhookSpec `json:"spec"`

	// +optional
	Status GitHubWebhookStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GitHubWebhookList contains a list of GitHubWebhook.
type GitHubWebhookList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GitHubWebhook `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitHubWebhook{}, &GitHubWebhookList{})
}
