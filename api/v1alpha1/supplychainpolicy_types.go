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
// Only supplyChainRef is required. The image repository, the Fulcio and CT log
// endpoints and the trust anchors always come from the referenced SupplyChain
// and the sigstore trust anchor ConfigMap. Signers and the Rekor log default to
// what the SupplyChain signs with, and can be stated here to pin them or to
// accept more than one signer. Status reports what was resolved.
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

	// serviceAccountName is the ServiceAccount this policy is rendered on behalf
	// of. Before anything is rendered it must pass three SubjectAccessReviews:
	// it can read the SupplyChain (scope), it may declare policy for it
	// (intent), and it may produce the admission policies (output). The
	// controller creates the ServiceAccount; granting it those permissions is
	// left to an administrator.
	// +kubebuilder:default="supply-chain-policy-runner"
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// signers are the keyless identities whose signature and authorization
	// attestation are accepted; any one of them is enough. Each must hold a
	// Fulcio certificate chaining to the trust root.
	// Defaults to the SupplyChain's ServiceAccount, which is the identity the
	// pipeline signs with.
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	// +optional
	Signers []PolicySigner `json:"signers,omitempty"`

	// rekor is the transparency log every signature and attestation must be
	// recorded in.
	// Defaults to the Rekor log the SupplyChain signs to.
	// +optional
	Rekor *PolicyRekor `json:"rekor,omitempty"`
}

// PolicySigner is one keyless identity allowed to sign.
// +kubebuilder:validation:XValidation:rule="has(self.serviceAccountName) != has(self.subject)",message="set exactly one of serviceAccountName or subject"
type PolicySigner struct {
	// serviceAccountName names a ServiceAccount in the policy's namespace. It
	// is shorthand for the subject Fulcio issues to that ServiceAccount.
	// +kubebuilder:validation:MinLength=1
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// subject is the exact subject of the Fulcio certificate, for signers that
	// are not a ServiceAccount in this namespace.
	// +kubebuilder:validation:MinLength=1
	// +optional
	Subject string `json:"subject,omitempty"`

	// issuer is the OIDC issuer that vouched for the signer.
	// Defaults to the cluster's ServiceAccount token issuer.
	// +optional
	Issuer string `json:"issuer,omitempty"`
}

// PolicyRekor identifies the transparency log to verify against. Its public
// key comes from the sigstore trust anchor ConfigMap.
type PolicyRekor struct {
	// url is the Rekor endpoint.
	// +kubebuilder:validation:Pattern=`^https?://`
	// +required
	URL string `json:"url"`
}

// AuthorizationProof is the API server's answer to one SubjectAccessReview.
type AuthorizationProof struct {
	// principal is the identity that was reviewed.
	Principal string `json:"principal"`
	// group is the API group of the resource.
	// +optional
	Group string `json:"group,omitempty"`
	// resource is the resource the action targets.
	Resource string `json:"resource"`
	// verb is the action.
	Verb string `json:"verb"`
	// allowed is the API server's verdict.
	Allowed bool `json:"allowed"`
	// reason is the API server's explanation, if it gave one.
	// +optional
	Reason string `json:"reason,omitempty"`
	// evaluatedAt is when the review was performed.
	EvaluatedAt metav1.Time `json:"evaluatedAt"`
}

// PolicyAuthorization holds the three proofs of the policy's ServiceAccount.
type PolicyAuthorization struct {
	// scope: the ServiceAccount can read the SupplyChain it sets policy for.
	// +optional
	Scope *AuthorizationProof `json:"scope,omitempty"`
	// intent: the ServiceAccount may declare admission policy for it.
	// +optional
	Intent *AuthorizationProof `json:"intent,omitempty"`
	// output: the ServiceAccount may produce the admission policies.
	// +optional
	Output *AuthorizationProof `json:"output,omitempty"`
}

// SignerIdentity is a signer as it appears in a Fulcio certificate.
type SignerIdentity struct {
	// issuer is the OIDC issuer in the certificate.
	Issuer string `json:"issuer"`
	// subject is the subject in the certificate.
	Subject string `json:"subject"`
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

	// authorization is the outcome of the three SubjectAccessReviews for the
	// policy's ServiceAccount, as of the last reconcile.
	// +optional
	Authorization *PolicyAuthorization `json:"authorization,omitempty"`

	// signers are the identities the policy accepts, as resolved from the spec
	// and the SupplyChain.
	// +listType=atomic
	// +optional
	Signers []SignerIdentity `json:"signers,omitempty"`

	// fulcioURL is the certificate authority the signers' certificates must
	// chain to.
	// +optional
	FulcioURL string `json:"fulcioURL,omitempty"`

	// rekorURL is the transparency log signatures and attestations must be
	// recorded in.
	// +optional
	RekorURL string `json:"rekorURL,omitempty"`

	// ctLogURL is the certificate transparency log the signers' certificates
	// must carry a proof from.
	// +optional
	CTLogURL string `json:"ctLogURL,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=scp
// +kubebuilder:printcolumn:name="SupplyChain",type=string,JSONPath=`.spec.supplyChainRef.name`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=='Ready')].status`
// +kubebuilder:printcolumn:name="Signers",type=string,JSONPath=`.status.signers[*].subject`,priority=1
// +kubebuilder:printcolumn:name="Rekor",type=string,JSONPath=`.status.rekorURL`,priority=1
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
