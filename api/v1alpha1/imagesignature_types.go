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

	// SignedBy is the ServiceAccount the build runs and signs as, the
	// principal the three authorization checks were made for. The identity
	// in the signing certificate is in status.subject.
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
}

// ImageSignatureStatus defines the observed state of ImageSignature.
//
// Everything about the signature here is read back from where it is kept:
// the signature stored next to the image in the registry, and its entry in
// the transparency log. None of it is what the controller expects to be true.
type ImageSignatureStatus struct {
	// Phase is Signed only once the build's signature has been found on the
	// image together with its transparency log entry. A build that succeeded
	// but whose signature could not be read stays Pending.
	// +kubebuilder:validation:Enum=Pending;Signed;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// Subject is the identity in the certificate that signed the image.
	// +optional
	Subject string `json:"subject,omitempty"`

	// Issuer is the OIDC issuer Fulcio verified that identity against.
	// +optional
	Issuer string `json:"issuer,omitempty"`

	// RekorLogIndex is the index of the signature's entry in the transparency
	// log. Unset until the entry has been found.
	// +optional
	RekorLogIndex *int64 `json:"rekorLogIndex,omitempty"`

	// RekorLogID identifies the log, by the SHA-256 of its public key.
	// +optional
	RekorLogID string `json:"rekorLogID,omitempty"`

	// Certificate is the PEM-encoded Fulcio certificate that signed the
	// image, as stored with the signature. Its private key was made for
	// that one signature and discarded.
	// +optional
	Certificate string `json:"certificate,omitempty"`

	// CertificateFingerprint is the SHA-256 of that certificate.
	// +optional
	CertificateFingerprint string `json:"certificateFingerprint,omitempty"`

	// KeyFingerprint is the SHA-256 of the public key in it.
	// +optional
	KeyFingerprint string `json:"keyFingerprint,omitempty"`

	// SignedAt is when the transparency log accepted the signature.
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
// +kubebuilder:printcolumn:name="Signer",type=string,JSONPath=`.status.subject`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="RekorIndex",type=integer,JSONPath=`.status.rekorLogIndex`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageSignature is the audit record of the build's own signature on an
// image: who signed, with which certificate, and where the transparency log
// recorded it. Created Pending when a build starts and completed from the
// registry and the log once the build has signed.
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
