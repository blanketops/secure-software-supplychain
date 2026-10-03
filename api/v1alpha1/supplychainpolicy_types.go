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

// SupplyChainPolicySpec defines the desired state of SupplyChainPolicy.
//
// Everything the admission policy needs is already declared on the referenced
// SupplyChain (image repository, Fulcio/Rekor/CT log endpoints, signing
// ServiceAccount) or lives in the sigstore trust anchor ConfigMap, so none of
// it is repeated here.
type SupplyChainPolicySpec struct {
	// supplyChainRef references the SupplyChain whose images this policy admits.
	// +required
	SupplyChainRef LocalObjectRef `json:"supplyChainRef"`

	// mode is what happens to a workload whose image fails verification:
	// "enforce" rejects it, "warn" admits it with a warning.
	// +kubebuilder:validation:Enum=enforce;warn
	// +kubebuilder:default=enforce
	// +optional
	Mode string `json:"mode,omitempty"`
}

// SupplyChainPolicyStatus defines the observed state of SupplyChainPolicy.
type SupplyChainPolicyStatus struct {
	// conditions represent the current state of the SupplyChainPolicy resource.
	//
	// Condition types:
	// - "Ready": the TrustRoot and ClusterImagePolicies are in sync with the SupplyChain
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// trustRoot is the name of the managed policy.sigstore.dev TrustRoot.
	// +optional
	TrustRoot string `json:"trustRoot,omitempty"`

	// clusterImagePolicies are the names of the managed policy.sigstore.dev
	// ClusterImagePolicies. An image must satisfy all of them: one requires the
	// keyless signature, the other the authorization attestation.
	// +optional
	ClusterImagePolicies []string `json:"clusterImagePolicies,omitempty"`

	// images are the image globs the ClusterImagePolicies apply to.
	// +optional
	Images []string `json:"images,omitempty"`

	// identity is the Fulcio certificate subject the images must be signed and
	// attested by.
	// +optional
	Identity string `json:"identity,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=scp
// +kubebuilder:printcolumn:name="SupplyChain",type=string,JSONPath=`.spec.supplyChainRef.name`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=='Ready')].status`
// +kubebuilder:printcolumn:name="Signer",type=string,JSONPath=`.status.identity`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SupplyChainPolicy is the Schema for the supplychainpolicies API.
// It is the admission side of a SupplyChain: one SupplyChainPolicy renders a
// sigstore policy-controller TrustRoot and the ClusterImagePolicies that only
// admit images the referenced SupplyChain signed keylessly and attested as
// authorized.
type SupplyChainPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SupplyChainPolicy
	// +required
	Spec SupplyChainPolicySpec `json:"spec"`

	// status defines the observed state of SupplyChainPolicy
	// +optional
	Status SupplyChainPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SupplyChainPolicyList contains a list of SupplyChainPolicy
type SupplyChainPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SupplyChainPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SupplyChainPolicy{}, &SupplyChainPolicyList{})
}
