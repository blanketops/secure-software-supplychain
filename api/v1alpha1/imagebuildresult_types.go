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

// ImageBuildResultSpec defines the desired state of ImageBuildResult.
// The spec is intentionally minimal — ImageBuildResult is a write-once
// record created by the controller. The references are stored here so
// the CR is self-describing even if the referenced resources are pruned.
type ImageBuildResultSpec struct {
	// ImageBuildRef references the ImageBuild that produced this result.
	// +kubebuilder:validation:Required
	ImageBuildRef LocalObjectRef `json:"imageBuildRef"`

	// PipelineRunRef references the Tekton PipelineRun that was executed.
	// +kubebuilder:validation:Required
	PipelineRunRef LocalObjectRef `json:"pipelineRunRef"`
}

// ImageBuildResultStatus defines the observed state of ImageBuildResult.
type ImageBuildResultStatus struct {
	// Conditions represent the current state of the ImageBuildResult resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Phase is the terminal phase of the build execution.
	// +kubebuilder:validation:Enum=Succeeded;Failed;Unknown
	// +optional
	Phase string `json:"phase,omitempty"`

	// Reason is the machine-readable reason for the terminal phase,
	// sourced directly from the PipelineRun condition reason.
	// +optional
	Reason string `json:"reason,omitempty"`

	// ImageURL is the fully-qualified image reference that was built and pushed.
	// e.g. docker.io/nkanyezisolutions/for-kaniko-app:abc123
	// +optional
	ImageURL string `json:"imageURL,omitempty"`

	// ImageDigest is the content-addressable digest of the built image.
	// e.g. sha256:abc123...
	// Populated from the buildah task IMAGE_DIGEST result.
	// +optional
	ImageDigest string `json:"imageDigest,omitempty"`

	// PipelineRunName is the name of the Tekton PipelineRun that was executed.
	// Stored here so the result remains useful after PipelineRun pruning.
	// +optional
	PipelineRunName string `json:"pipelineRunName,omitempty"`

	// CompletedAt is the timestamp when the PipelineRun reached a terminal state.
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ibr
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="ImageURL",type=string,JSONPath=`.status.imageURL`
// +kubebuilder:printcolumn:name="Digest",type=string,JSONPath=`.status.imageDigest`
// +kubebuilder:printcolumn:name="CompletedAt",type=date,JSONPath=`.status.completedAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageBuildResult is the durable record of a completed ImageBuild execution.
// It is created by the controller when a PipelineRun reaches a terminal state
// and survives PipelineRun pruning. One ImageBuildResult per ImageBuild.
type ImageBuildResult struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec ImageBuildResultSpec `json:"spec"`

	// +optional
	Status ImageBuildResultStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageBuildResultList contains a list of ImageBuildResult.
type ImageBuildResultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageBuildResult `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageBuildResult{}, &ImageBuildResultList{})
}
