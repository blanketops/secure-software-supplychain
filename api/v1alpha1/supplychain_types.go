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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// SupplyChainSpec defines the desired state of SupplyChain
type SupplyChainSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html
	// Repository is the GitHub repo this supply chain is bound to (owner/name format).
	// One SupplyChain per repository — this is law.
	Repository string `json:"repository"`
	// Image defines how the container image is built and where it's pushed
	Image ImageSpec `json:"image"`
	// Steps defines which pipeline steps are enabled and their configuration
	Steps StepsSpec `json:"steps"`

	// Signing defines Sigstore signing configuration
	// +optional
	Signing *SigningSpec `json:"signing,omitempty"`
	// ServiceAccountName is the k8s SA used by Tekton TaskRuns
	// +kubebuilder:default="default"
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// WebhookHost is the public hostname for the EventListener ingress.
	// e.g. pop-os.tailf8145.ts.net
	// +optional
	WebhookHost string `json:"webhookHost,omitempty"`
}

// ImageSpec defines image build and push configuration
type ImageSpec struct {
	// Registry is the image registry to push to (e.g. ttl.sh, ghcr.io)
	Registry string `json:"registry"`
	// Name is the image name (without tag)
	Name string `json:"name"`
	// Tag strategy for the built image
	// +kubebuilder:validation:Enum=git-sha;semver;latest
	// +kubebuilder:default=git-sha
	TagStrategy string `json:"tagStrategy,omitempty"`
	// BuilderImage is the Cloud Native Buildpacks builder image
	// +kubebuilder:default="paketobuildpacks/builder-jammy-base"
	BuilderImage string `json:"builderImage,omitempty"`
	// CloneSecretRef references a Secret with git ssh credentials
	// +optional
	CloneSecretRef string `json:"cloneSecret,omitempty"`

	// PushSecretRef references a Secret with registry credentials
	// +optional
	RegistrySecretRef string `json:"registrySecret,omitempty"`
}

// StepsSpec enables/disables individual pipeline steps
type StepsSpec struct {
	// Buildpacks enables the Cloud Native Buildpacks build step
	// +kubebuilder:default=true
	Buildpacks bool `json:"buildpacks,omitempty"`
	// SonarQube enables static analysis via SonarQube
	// +optional
	SonarQube *SonarQubeSpec `json:"sonarQube,omitempty"`
	// Trivy enables vulnerability scanning
	// +kubebuilder:default=true
	Trivy bool `json:"trivy,omitempty"`
	// Sign enables image signing via Cosign + Sigstore
	// +kubebuilder:default=true
	Sign bool `json:"sign,omitempty"`
	// Attest enables provenance attestation via Tekton Chains
	// +kubebuilder:default=true
	Attest bool `json:"attest,omitempty"`
	// Grafeas enables artifact metadata publishing to Grafeas
	// +optional
	Grafeas *GrafeasSpec `json:"grafeas,omitempty"`
}

// SonarQubeSpec configures the SonarQube step
type SonarQubeSpec struct {
	// Enabled toggles this step
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`
	// ServerURL is the SonarQube server endpoint
	ServerURL string `json:"serverURL"`
	// TokenSecretRef references a Secret with the SonarQube token
	TokenSecretRef string `json:"tokenSecretRef"`

	// ProjectKey is the SonarQube project key (alphanumeric, -, _, ., : only)
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9\-_.:]+$`
	ProjectKey string `json:"projectKey"`
}

// GrafeasSpec configures the Grafeas artifact metadata step
type GrafeasSpec struct {
	// Enabled toggles this step
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`
	// ServerURL is the Grafeas server endpoint
	ServerURL string `json:"serverURL"`
}

// SigningSpec configures Sigstore signing (Cosign + Fulcio + Rekor)
type SigningSpec struct {

	// FulcioURL is the Fulcio OIDC certificate authority endpoint
	// +kubebuilder:default="https://fulcio.sigstore.dev"
	FulcioURL string `json:"fulcioURL,omitempty"`

	// RekorURL is the Rekor transparency log endpoint
	// +kubebuilder:default="https://rekor.sigstore.dev"
	RekorURL string `json:"rekorURL,omitempty"`

	// CTLogURL is the certificate transparency log Fulcio writes to
	// +kubebuilder:default="https://ctfe.sigstore.dev"
	CTLogURL string `json:"ctLogURL,omitempty"`

	// OIDCIssuer is the OIDC issuer for keyless signing
	// +kubebuilder:default="https://oauth2.sigstore.dev/auth"
	OIDCIssuer string `json:"oidcIssuer,omitempty"`
}

// SupplyChainStatus defines the observed state of SupplyChain.
type SupplyChainStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
	// conditions represent the current state of the SupplyChain resource.
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
	// Phase is the current lifecycle phase of the SupplyChain
	// +kubebuilder:validation:Enum=Ready;Degraded;Error
	Phase string `json:"phase,omitempty"`
	// LastImageBuild is the name of the most recent ImageBuild created
	// +optional
	LastImageBuild string `json:"lastImageBuild,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=sc
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.repository`
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.spec.image.registry`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Last Build",type=string,JSONPath=`.status.lastImageBuild`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// SupplyChain is the Schema for the supplychains API.
// One SupplyChain per repository — this is law.
type SupplyChain struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`
	// spec defines the desired state of SupplyChain
	// +required
	Spec SupplyChainSpec `json:"spec"`
	// status defines the observed state of SupplyChain
	// +optional
	Status SupplyChainStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
// SupplyChainList contains a list of SupplyChain
type SupplyChainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SupplyChain `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SupplyChain{}, &SupplyChainList{})
}
