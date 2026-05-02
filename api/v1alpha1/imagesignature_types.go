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

// ImageSignatureSpec defines the desired state of ImageSignature.
// Created by the ImageBuildReconciler after a successful PipelineRun.
// Carries the full signing identity and transparency log references.
type ImageSignatureSpec struct {
	// Image is the fully qualified image reference that was signed.
	// e.g. docker.io/nkanyezisolutions/for-kaniko-app:abc123
	// +kubebuilder:validation:Required
	Image string `json:"image"`

	// Digest is the content-addressable digest of the image at time of signing.
	// e.g. sha256:abc123...
	// +kubebuilder:validation:Required
	Digest string `json:"digest"`

	// SignedBy is the SPIFFE/SPIRE identity of the ServiceAccount that signed.
	// Sourced from the Fulcio certificate subject.
	// e.g. system:serviceaccount:default:supply-chain-runner
	// +kubebuilder:validation:Required
	SignedBy string `json:"signedBy"`

	// FulcioURL is the Fulcio CA that issued the ephemeral signing certificate.
	// +kubebuilder:validation:Required
	FulcioURL string `json:"fulcioURL"`

	// RekorURL is the Rekor transparency log where the signature was recorded.
	// +kubebuilder:validation:Required
	RekorURL string `json:"rekorURL"`

	// SupplyChain is the name of the SupplyChain that governed this build.
	// +kubebuilder:validation:Required
	SupplyChain string `json:"supplyChain"`

	// ImageBuild is the name of the ImageBuild that produced this signature.
	// +kubebuilder:validation:Required
	ImageBuild string `json:"imageBuild"`

	// GrafeasOccurrence is the Grafeas occurrence name for this signing event.
	// e.g. projects/blanketops/occurrences/abc123
	// +optional
	GrafeasOccurrence string `json:"grafeasOccurrence,omitempty"`
}

// ImageSignatureStatus defines the observed state of ImageSignature.
type ImageSignatureStatus struct {
	// Phase is the current signing phase.
	// +kubebuilder:validation:Enum=Pending;Signed;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// RekorLogIndex is the Rekor transparency log entry index.
	// Populated after successful attestation.
	// +optional
	RekorLogIndex int64 `json:"rekorLogIndex,omitempty"`

	// Certificate is the PEM-encoded Fulcio ephemeral certificate used to sign.
	// Stored for audit — the private key is discarded after signing.
	// +optional
	Certificate string `json:"certificate,omitempty"`

	// SignedAt is the timestamp when the image was signed.
	// +optional
	SignedAt *metav1.Time `json:"signedAt,omitempty"`

	// Conditions represent the current state of the ImageSignature resource.
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
// +kubebuilder:printcolumn:name="RekorIndex",type=integer,JSONPath=`.status.rekorLogIndex`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageSignature is the cryptographic audit record of a signed image.
// Created by the controller after a successful PipelineRun. Carries the
// full signing identity, Fulcio certificate reference, and Rekor log index.
// Owned by the ImageBuild — deleted when the ImageBuild is deleted.
type ImageSignature struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec ImageSignatureSpec `json:"spec"`

	// +optional
	Status ImageSignatureStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageSignatureList contains a list of ImageSignature.
type ImageSignatureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageSignature `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageSignature{}, &ImageSignatureList{})
}
