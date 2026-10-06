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

	// ── Policy ────────────────────────────────────────────────────────────

	// PolicyVerification is PASS when the build's last step verified the
	// pushed image the way admission does: keyless signature and authorization
	// attestation by the SupplyChain's ServiceAccount. It is empty when that
	// step did not run or did not pass.
	// +optional
	PolicyVerification string `json:"policyVerification,omitempty"`

	// VerifiedSigner is the certificate identity the signature and the
	// attestation were verified against.
	// +optional
	VerifiedSigner string `json:"verifiedSigner,omitempty"`
}

// SignatureRecord is one signature or attestation found on the built image, as
// it is stored in the registry next to it, together with where it was
// recorded in the transparency log.
type SignatureRecord struct {
	// kind says whether this is a signature of the image or an attestation
	// about it.
	// +kubebuilder:validation:Enum=Signature;Attestation
	Kind string `json:"kind"`

	// predicateType is what an attestation states, for example SLSA
	// provenance or the build's authorization proofs. Empty for signatures.
	// +optional
	PredicateType string `json:"predicateType,omitempty"`

	// signedBy is who made it: Build for the SupplyChain's ServiceAccount,
	// Chains for Tekton Chains, Other for an identity that is neither.
	// +kubebuilder:validation:Enum=Build;Chains;Other
	SignedBy string `json:"signedBy"`

	// subject is the identity in the signing certificate.
	// +optional
	Subject string `json:"subject,omitempty"`

	// issuer is the OIDC issuer Fulcio verified that identity against.
	// +optional
	Issuer string `json:"issuer,omitempty"`

	// keyFingerprint is the SHA-256 of the public key that signed. The key
	// was made for this one signature and its private half is gone.
	// +optional
	KeyFingerprint string `json:"keyFingerprint,omitempty"`

	// certificateFingerprint is the SHA-256 of the Fulcio certificate that
	// binds the key to the subject.
	// +optional
	CertificateFingerprint string `json:"certificateFingerprint,omitempty"`

	// certificate is that certificate, PEM-encoded. With it and the log
	// entry, the signature can be verified again by anyone, at any time.
	// +optional
	Certificate string `json:"certificate,omitempty"`

	// notBefore and notAfter are the validity of that certificate. The
	// signature must have been logged inside it.
	// +optional
	NotBefore *metav1.Time `json:"notBefore,omitempty"`
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`

	// rekorLogIndex is the index of the entry in the transparency log. Unset
	// when no entry was found.
	// +optional
	RekorLogIndex *int64 `json:"rekorLogIndex,omitempty"`

	// rekorLogID identifies the log, by the SHA-256 of its public key.
	// +optional
	RekorLogID string `json:"rekorLogID,omitempty"`

	// integratedAt is when the log accepted the entry.
	// +optional
	IntegratedAt *metav1.Time `json:"integratedAt,omitempty"`
}

// BuildEvidence is everything that vouches for the built image: who signed
// and attested it, with which keys, where that is logged, and which trust
// anchors those claims are checked against.
type BuildEvidence struct {
	// signatures lists every signature and attestation on the image, in the
	// order the transparency log recorded them.
	// +optional
	// +listType=atomic
	Signatures []SignatureRecord `json:"signatures,omitempty"`

	// fulcioURL is the certificate authority that issued the certificates.
	// +optional
	FulcioURL string `json:"fulcioURL,omitempty"`

	// rekorURL is the transparency log the entries are in.
	// +optional
	RekorURL string `json:"rekorURL,omitempty"`

	// trustAnchors are the fingerprints of the Fulcio root, the Rekor key
	// and the CT log key in use when the evidence was collected.
	// +optional
	TrustAnchors *TrustAnchorFingerprints `json:"trustAnchors,omitempty"`

	// provenanceLogEntry is where Tekton Chains logged the provenance of the
	// whole run.
	// +optional
	ProvenanceLogEntry string `json:"provenanceLogEntry,omitempty"`

	// complete is true once Tekton Chains has finished with the run, so
	// nothing more will be added to the image.
	// +optional
	Complete bool `json:"complete,omitempty"`

	// message says what could not be collected, if anything.
	// +optional
	Message string `json:"message,omitempty"`

	// collectedAt is when the registry and the log were last read.
	// +optional
	CollectedAt *metav1.Time `json:"collectedAt,omitempty"`
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

	// Evidence is what vouches for the image: its signatures and attestations,
	// the keys and identities behind them, and their transparency log entries.
	// +optional
	Evidence *BuildEvidence `json:"evidence,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ibr
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="ImageURL",type=string,JSONPath=`.status.imageURL`
// +kubebuilder:printcolumn:name="Digest",type=string,JSONPath=`.status.imageDigest`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.status.buildResults.policyVerification`
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
