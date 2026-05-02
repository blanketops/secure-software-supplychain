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

// PipelineStepResults holds the structured output of all 9 pipeline steps.
// Populated from PipelineRun results after a terminal state is reached.
type PipelineStepResults struct {
	// ── Git Provenance ────────────────────────────────────────────────────

	// Commit is the full git commit SHA cloned.
	// +optional
	Commit string `json:"commit,omitempty"`

	// CommitterDate is the date of the commit.
	// +optional
	CommitterDate string `json:"committerDate,omitempty"`

	// RepoURL is the git repository URL.
	// +optional
	RepoURL string `json:"repoURL,omitempty"`

	// ── Build ─────────────────────────────────────────────────────────────

	// ImageURL is the fully-qualified image reference that was built and pushed.
	// +optional
	ImageURL string `json:"imageURL,omitempty"`

	// ImageDigest is the content-addressable digest of the built image.
	// +optional
	ImageDigest string `json:"imageDigest,omitempty"`

	// ── Security Gates ────────────────────────────────────────────────────

	// TrivyScanSummary is PASS or FAIL from the Trivy vulnerability scan.
	// +optional
	TrivyScanSummary string `json:"trivyScanSummary,omitempty"`

	// TrivyCriticalCount is the number of CRITICAL vulnerabilities found.
	// +optional
	TrivyCriticalCount string `json:"trivyCriticalCount,omitempty"`

	// TrivyHighCount is the number of HIGH vulnerabilities found.
	// +optional
	TrivyHighCount string `json:"trivyHighCount,omitempty"`

	// TrivyTotalCount is the total HIGH+CRITICAL count.
	// +optional
	TrivyTotalCount string `json:"trivyTotalCount,omitempty"`

	// TrivySarifPath is the path to the SARIF report in the workspace.
	// +optional
	TrivySarifPath string `json:"trivySarifPath,omitempty"`

	// SonarGateStatus is the SonarQube quality gate result.
	// +optional
	SonarGateStatus string `json:"sonarGateStatus,omitempty"`

	// ── Attestation ───────────────────────────────────────────────────────

	// GrafeasOccurrence is the Grafeas occurrence name for this build event.
	// e.g. projects/blanketops/occurrences/abc123
	// +optional
	GrafeasOccurrence string `json:"grafeasOccurrence,omitempty"`
}

// ImageBuildResultSpec defines the desired state of ImageBuildResult.
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

	// Reason is the machine-readable reason for the terminal phase.
	// +optional
	Reason string `json:"reason,omitempty"`

	// ImageURL is the fully-qualified image reference that was built.
	// Kept at the top level for quick access — also in BuildResults.
	// +optional
	ImageURL string `json:"imageURL,omitempty"`

	// ImageDigest is the content-addressable digest of the built image.
	// Kept at the top level for quick access — also in BuildResults.
	// +optional
	ImageDigest string `json:"imageDigest,omitempty"`

	// PipelineRunName is the name of the Tekton PipelineRun that was executed.
	// Stored here so the result remains useful after PipelineRun pruning.
	// +optional
	PipelineRunName string `json:"pipelineRunName,omitempty"`

	// CompletedAt is the timestamp when the PipelineRun reached a terminal state.
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// BuildResults contains the full structured output of all pipeline steps.
	// Populated from PipelineRun results — covers git, build, security, attestation.
	// +optional
	BuildResults *PipelineStepResults `json:"buildResults,omitempty"`
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
// Survives PipelineRun pruning. One ImageBuildResult per ImageBuild.
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
