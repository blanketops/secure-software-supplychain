/*
Copyright 2026.

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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// RepositorySourceSpec defines the desired state of RepositorySource
type RepositorySourceSpec struct {
	// Provider is the git provider (github, gitlab, bitbucket)
	// +kubebuilder:validation:Enum=github;gitlab;bitbucket
	// +kubebuilder:default=github
	Provider string `json:"provider"`

	// Repository is the full repository path e.g. ntlaletsi70/for-kaniko-app
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9\-_.]+\/[a-zA-Z0-9\-_.]+$`
	Repository string `json:"repository"`

	// Branch is the branch to watch
	// +kubebuilder:default=main
	Branch string `json:"branch"`

	// TokenSecretRef references a Secret containing the provider PAT
	TokenSecretRef string `json:"tokenSecretRef"`

	// ListenerURL is the EventListener URL injected as a repo secret
	ListenerURL string `json:"listenerURL"`

	// Webhook configures the webhook injection
	Webhook WebhookSpec `json:"webhook"`

	// OIDC configures the OIDC token minting
	OIDC OIDCSpec `json:"oidc"`
}

// WebhookSpec configures webhook injection
type WebhookSpec struct {
	// Inject controls whether the controller injects the workflow file
	// +kubebuilder:default=true
	Inject bool `json:"inject,omitempty"`

	// HMACSecretRef references a Secret containing the webhook HMAC secret
	HMACSecretRef string `json:"hmacSecretRef"`

	// WorkflowPath is the path to inject the workflow file
	// +kubebuilder:default=".github/workflows/blanketops.yml"
	WorkflowPath string `json:"workflowPath,omitempty"`
}

// OIDCSpec configures OIDC token minting
type OIDCSpec struct {
	// Audience is the OIDC audience
	// +kubebuilder:default=sigstore
	Audience string `json:"audience,omitempty"`

	// ForwardTo is the destination for the OIDC token
	// +kubebuilder:validation:Enum=chains;custom
	// +kubebuilder:default=chains
	ForwardTo string `json:"forwardTo,omitempty"`
}

// RepositorySourceStatus defines the observed state of RepositorySource.
type RepositorySourceStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// Phase is the current phase of the RepositorySource
	// +kubebuilder:validation:Enum=Pending;Registering;Ready;Failed
	Phase string `json:"phase,omitempty"`

	// WebhookID is the ID of the registered webhook
	WebhookID int64 `json:"webhookId,omitempty"`

	// WorkflowInjected indicates whether the workflow file was injected
	WorkflowInjected bool `json:"workflowInjected,omitempty"`

	// ListenerURLRegistered indicates whether the listener URL was registered
	ListenerURLRegistered bool `json:"listenerURLRegistered,omitempty"`

	// ObservedGeneration is the last observed generation
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// conditions represent the current state of the RepositorySource resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=rs
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.provider`
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repository`
// +kubebuilder:printcolumn:name="Branch",type=string,JSONPath=`.spec.branch`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="WebhookID",type=integer,JSONPath=`.status.webhookId`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// RepositorySource is the Schema for the repositorysources API
type RepositorySource struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of RepositorySource
	// +required
	Spec RepositorySourceSpec `json:"spec"`

	// status defines the observed state of RepositorySource
	// +optional
	Status RepositorySourceStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// RepositorySourceList contains a list of RepositorySource
type RepositorySourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []RepositorySource `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RepositorySource{}, &RepositorySourceList{})
}
