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

// ImageBuildSpec defines the desired state of ImageBuild.
type ImageBuildSpec struct {
	// SupplyChainRef references the SupplyChain that owns this build.
	// Set automatically when the SupplyChain controller creates an ImageBuild,
	// or set manually to trigger a build against a specific SupplyChain.
	SupplyChainRef LocalObjectRef `json:"supplyChainRef"`

	// GitRef defines the git reference to build from.
	GitRef GitRef `json:"gitRef"`

	// ImageTag overrides the tag strategy from the SupplyChain for this specific build.
	// +optional
	ImageTag string `json:"imageTag,omitempty"`
}

// LocalObjectRef references an object in the same namespace.
type LocalObjectRef struct {
	// Name of the object.
	Name string `json:"name"`
}

// GitRef defines the git source for the build.
type GitRef struct {
	// URL is the git repository URL (SSH format: git@github.com:owner/repo.git).
	URL string `json:"url"`

	// Revision is the git revision (branch, tag, or SHA).
	// +kubebuilder:default="main"
	// +optional
	Revision string `json:"revision,omitempty"`

	// SHA is the exact commit SHA — populated by the controller after clone.
	// +optional
	SHA string `json:"sha,omitempty"`
}

// ImageBuildStatus defines the observed state of ImageBuild.
type ImageBuildStatus struct {
	// Conditions represent the current state of the ImageBuild resource.
	//
	// Standard condition types:
	//   - "Available":   the resource is fully functional.
	//   - "Progressing": the resource is being created or updated.
	//   - "Degraded":    the resource failed to reach or maintain its desired state.
	//
	// Each condition status is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Phase is the overall build phase.
	// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// Steps tracks the status of each pipeline step.
	// +optional
	Steps []StepStatus `json:"steps,omitempty"`

	// PipelineRunRef is the name of the Tekton PipelineRun driving this build.
	// +optional
	PipelineRunRef string `json:"pipelineRunRef,omitempty"`

	// ImageRef is the fully qualified image reference produced by this build
	// e.g. ttl.sh/secure-software-:abc1234
	// +optional
	ImageRef string `json:"imageRef,omitempty"`

	// ImageDigest is the sha256 digest of the built image.
	// +optional
	ImageDigest string `json:"imageDigest,omitempty"`

	// StartTime is when the build began.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the build finished (success or failure).
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// StepStatus tracks an individual pipeline step.
type StepStatus struct {
	// Name is the step name (e.g. git-clone, kaniko, trivy, sign).
	Name string `json:"name"`

	// Phase is the step phase.
	// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed;Skipped
	Phase string `json:"phase"`

	// Message holds any human-readable detail about the step outcome.
	// +optional
	Message string `json:"message,omitempty"`

	// StartTime is when this step started.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when this step finished.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ib
// +kubebuilder:printcolumn:name="SupplyChain",type=string,JSONPath=`.spec.supplyChainRef.name`
// +kubebuilder:printcolumn:name="Revision",type=string,JSONPath=`.spec.gitRef.revision`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.status.imageRef`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageBuild is the Schema for the imagebuilds API.
// An ImageBuild is a single execution of a SupplyChain pipeline.
// Create one manually to trigger a build, or let a SupplyChain controller create it.
type ImageBuild struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec ImageBuildSpec `json:"spec"`

	// +optional
	Status ImageBuildStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// ImageBuildList contains a list of ImageBuild.
type ImageBuildList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageBuild `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageBuild{}, &ImageBuildList{})
}
