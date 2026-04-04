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

// ImageSignatureSpec defines the desired state of ImageSignature
type ImageSignatureSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// Image is the fully qualified image reference
	Image string `json:"image"`
	// Digest is the image digest at time of signing
	Digest string `json:"digest"`
	// SignedBy is the ServiceAccount identity that signed
	SignedBy string `json:"signedBy"`
	// FulcioURL is the CA authority used
	FulcioURL string `json:"fulcioURL"`
	// RekorURL is the transparency log used
	RekorURL string `json:"rekorURL"`
	// SupplyChain is the owning SupplyChain
	SupplyChain string `json:"supplyChain"`
	// ImageBuild is the owning ImageBuild
	ImageBuild string `json:"imageBuild"`
}

// ImageSignatureStatus defines the observed state of ImageSignature.
type ImageSignatureStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the ImageSignature resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	// Phase is the current phase
	// +kubebuilder:validation:Enum=Pending;Signed;Failed
	Phase string `json:"phase,omitempty"`
	// RekorLogIndex is the Rekor transparency log index
	RekorLogIndex int64 `json:"rekorLogIndex,omitempty"`
	// Certificate is the Fulcio-issued certificate
	Certificate string `json:"certificate,omitempty"`
	// SignedAt is the time of signing
	SignedAt *metav1.Time `json:"signedAt,omitempty"`
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
// +kubebuilder:resource:scope=Namespaced,shortName=ims
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="SignedBy",type=string,JSONPath=`.spec.signedBy`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ImageSignature is the Schema for the imagesignatures API
type ImageSignature struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ImageSignature
	// +required
	Spec ImageSignatureSpec `json:"spec"`

	// status defines the observed state of ImageSignature
	// +optional
	Status ImageSignatureStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ImageSignatureList contains a list of ImageSignature
type ImageSignatureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ImageSignature `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageSignature{}, &ImageSignatureList{})
}
