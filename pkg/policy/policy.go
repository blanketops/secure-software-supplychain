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

// Package policy renders the sigstore policy-controller resources that admit
// only images signed by a SupplyChain. The resources are built as unstructured
// objects so the operator does not link policy-controller.
package policy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/authz"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

const (
	// LabelPolicyNamespace and LabelPolicyName record the owning
	// SupplyChainPolicy on the cluster-scoped resources, which cannot carry an
	// owner reference to a namespaced object.
	LabelPolicyNamespace = "blanketops.dev/supply-chain-policy-namespace"
	LabelPolicyName      = "blanketops.dev/supply-chain-policy"

	hashAlgorithm = "sha-256"
)

var (
	TrustRootGVK          = schema.GroupVersionKind{Group: "policy.sigstore.dev", Version: "v1alpha1", Kind: "TrustRoot"}
	ClusterImagePolicyGVK = schema.GroupVersionKind{Group: "policy.sigstore.dev", Version: "v1beta1", Kind: "ClusterImagePolicy"}
)

// Rendered is the desired policy-controller state for one SupplyChainPolicy.
type Rendered struct {
	TrustRoot *unstructured.Unstructured
	// ClusterImagePolicies must all pass for an image to be admitted: one
	// requires the signature, the other the authorization attestation.
	// policy-controller ORs the authorities inside a policy and ANDs the
	// policies, so the two requirements cannot share one policy.
	ClusterImagePolicies []*unstructured.Unstructured
	// Images are the globs the ClusterImagePolicy applies to.
	Images []string
	// Signers are the identities the policies accept.
	Signers []supplyv1alpha1.SignerIdentity
	// Endpoints are the sigstore services the policies verify against.
	Endpoints signing.Endpoints
	// TrustAnchors are the fingerprints of the key material in the TrustRoot.
	TrustAnchors supplyv1alpha1.TrustAnchorFingerprints
}

// ResourceName is the name of the TrustRoot and the signature
// ClusterImagePolicy of a SupplyChainPolicy, and the prefix of its other
// policies. All are cluster-scoped, so the namespace is part of it.
func ResourceName(scp *supplyv1alpha1.SupplyChainPolicy) string {
	return scp.Namespace + "-" + scp.Name
}

// Render builds the TrustRoot and ClusterImagePolicies for scp from the
// SupplyChain it references and the trust anchors in roots (the data of
// signing.RootsConfigMap). The sigstore endpoints and keys are stated once, in
// the TrustRoot; the policies only point at it.
//
// Together the policies admit an image only if the SupplyChain's
// ServiceAccount signed it keylessly (Fulcio cert chained to the trust root,
// embedded CT log proof, Rekor entry) and attested that it passed the three
// authorization checks before signing.
func Render(
	scp *supplyv1alpha1.SupplyChainPolicy,
	sc *supplyv1alpha1.SupplyChain,
	roots map[string]string,
) (*Rendered, error) {
	name := ResourceName(scp)
	endpoints := EndpointsFor(scp, sc)

	trustRootSpec, err := trustRootSpec(endpoints, roots)
	if err != nil {
		return nil, err
	}

	serviceAccount := sc.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	signers := resolveSigners(scp, serviceAccount)
	identities := make([]any, 0, len(signers))
	for _, signer := range signers {
		identities = append(identities, map[string]any{"issuer": signer.Issuer, "subject": signer.Subject})
	}
	images := []string{ImageGlob(sc)}

	mode := scp.Spec.Mode
	if mode == "" {
		mode = "enforce"
	}

	globs := make([]any, 0, len(images))
	for _, glob := range images {
		globs = append(globs, map[string]any{"glob": glob})
	}
	// authority is the set of keyless signers both policies trust.
	authority := func(authorityName string) map[string]any {
		return map[string]any{
			"name": authorityName,
			"keyless": map[string]any{
				"url":          endpoints.FulcioURL,
				"trustRootRef": name,
				"identities":   identities,
			},
			"ctlog": map[string]any{
				"url":          endpoints.RekorURL,
				"trustRootRef": name,
			},
		}
	}
	policySpec := func(authority map[string]any) map[string]any {
		return map[string]any{"mode": mode, "images": globs, "authorities": []any{authority}}
	}

	authorized := authority("authorization")
	authorized["attestations"] = []any{
		map[string]any{
			"name":          "authorization",
			"predicateType": signing.AuthorizationPredicateType,
			"policy": map[string]any{
				"type": "cue",
				"data": authorizationCUE(authz.Principal(sc.Namespace, serviceAccount)),
			},
		},
	}

	return &Rendered{
		TrustRoot: newObject(TrustRootGVK, name, scp, trustRootSpec),
		ClusterImagePolicies: []*unstructured.Unstructured{
			newObject(ClusterImagePolicyGVK, name, scp, policySpec(authority("signature"))),
			newObject(ClusterImagePolicyGVK, name+"-authorization", scp, policySpec(authorized)),
		},
		Images:    images,
		Signers:   signers,
		Endpoints: endpoints,
		TrustAnchors: supplyv1alpha1.TrustAnchorFingerprints{
			FulcioRoot: fingerprint(roots[signing.RootsFulcioKey]),
			RekorKey:   fingerprint(roots[signing.RootsRekorKey]),
			CTLogKey:   fingerprint(roots[signing.RootsCTLogKey]),
		},
	}, nil
}

// EndpointsFor resolves the sigstore endpoints a policy verifies against: the
// ones stated in its trust root, else the ones the SupplyChain signs with.
func EndpointsFor(scp *supplyv1alpha1.SupplyChainPolicy, sc *supplyv1alpha1.SupplyChain) signing.Endpoints {
	endpoints := signing.EndpointsFor(sc)
	trustRoot := scp.Spec.TrustRoot
	if trustRoot == nil {
		return endpoints
	}
	override := func(authority *supplyv1alpha1.TrustedAuthority, url *string) {
		if authority != nil && authority.URL != "" {
			*url = authority.URL
		}
	}
	override(trustRoot.Fulcio, &endpoints.FulcioURL)
	override(trustRoot.Rekor, &endpoints.RekorURL)
	override(trustRoot.CTLog, &endpoints.CTLogURL)
	return endpoints
}

// TrustSources says which ConfigMap key holds each trust anchor of a policy,
// keyed by the name the anchor has in the default ConfigMap
// (signing.RootsFulcioKey and friends). Anything the policy does not state
// comes from signing.RootsConfigMap.
func TrustSources(scp *supplyv1alpha1.SupplyChainPolicy) map[string]supplyv1alpha1.ConfigMapKeyRef {
	sources := map[string]supplyv1alpha1.ConfigMapKeyRef{
		signing.RootsFulcioKey: {Name: signing.RootsConfigMap, Key: signing.RootsFulcioKey},
		signing.RootsRekorKey:  {Name: signing.RootsConfigMap, Key: signing.RootsRekorKey},
		signing.RootsCTLogKey:  {Name: signing.RootsConfigMap, Key: signing.RootsCTLogKey},
	}
	trustRoot := scp.Spec.TrustRoot
	if trustRoot == nil {
		return sources
	}
	override := func(anchor string, authority *supplyv1alpha1.TrustedAuthority) {
		if authority != nil && authority.PEMRef != nil {
			sources[anchor] = *authority.PEMRef
		}
	}
	override(signing.RootsFulcioKey, trustRoot.Fulcio)
	override(signing.RootsRekorKey, trustRoot.Rekor)
	override(signing.RootsCTLogKey, trustRoot.CTLog)
	return sources
}

// fingerprint identifies a trust anchor by the SHA-256 of its first PEM
// block's contents, so it does not change with whitespace or line endings.
func fingerprint(pemData string) string {
	data := []byte(strings.TrimSpace(pemData))
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// resolveSigners turns spec.signers into certificate identities. With none
// stated, the only signer is the ServiceAccount the SupplyChain's pipeline
// signs with.
func resolveSigners(scp *supplyv1alpha1.SupplyChainPolicy, supplyChainServiceAccount string) []supplyv1alpha1.SignerIdentity {
	if len(scp.Spec.Signers) == 0 {
		return []supplyv1alpha1.SignerIdentity{{
			Issuer:  signing.KubernetesOIDCIssuer,
			Subject: signing.ServiceAccountIdentity(scp.Namespace, supplyChainServiceAccount),
		}}
	}
	signers := make([]supplyv1alpha1.SignerIdentity, 0, len(scp.Spec.Signers))
	for _, signer := range scp.Spec.Signers {
		identity := supplyv1alpha1.SignerIdentity{Issuer: signer.Issuer, Subject: signer.Subject}
		if identity.Issuer == "" {
			identity.Issuer = signing.KubernetesOIDCIssuer
		}
		if signer.ServiceAccountName != "" {
			identity.Subject = signing.ServiceAccountIdentity(scp.Namespace, signer.ServiceAccountName)
		}
		signers = append(signers, identity)
	}
	return signers
}

// authorizationCUE is the policy the authorization attestation must satisfy:
// all three proofs present, for this ServiceAccount, and allowed.
func authorizationCUE(principal string) string {
	proof := func(field string, check signing.AuthorizationCheck) string {
		return fmt.Sprintf("\t%s: {principal: %q, resource: %q, verb: %q, allowed: true}\n",
			field, principal, check.Resource, check.Verb)
	}
	return fmt.Sprintf("predicateType: %q\npredicate: {\n", signing.AuthorizationPredicateType) +
		proof("scope", signing.ScopeCheck) +
		proof("intent", signing.IntentCheck) +
		proof("output", signing.OutputCheck) +
		"}\n"
}

// ImageGlob matches every tag and digest of the image a SupplyChain pushes.
// policy-controller resolves docker.io references to index.docker.io before
// matching, so the glob is written against the resolved name.
func ImageGlob(sc *supplyv1alpha1.SupplyChain) string {
	registry := sc.Spec.Image.Registry
	if registry == "docker.io" {
		registry = "index.docker.io"
	}
	return fmt.Sprintf("%s/%s**", registry, sc.Spec.Image.Name)
}

// OwnedBy reports whether obj was rendered for scp.
func OwnedBy(obj *unstructured.Unstructured, scp *supplyv1alpha1.SupplyChainPolicy) bool {
	labels := obj.GetLabels()
	return labels[LabelPolicyNamespace] == scp.Namespace && labels[LabelPolicyName] == scp.Name
}

func newObject(
	gvk schema.GroupVersionKind,
	name string,
	scp *supplyv1alpha1.SupplyChainPolicy,
	spec map[string]any,
) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	obj.SetGroupVersionKind(gvk)
	obj.SetName(name)
	obj.SetLabels(map[string]string{
		"blanketops.dev/managed": "true",
		LabelPolicyNamespace:     scp.Namespace,
		LabelPolicyName:          scp.Name,
	})
	return obj
}

func trustRootSpec(endpoints signing.Endpoints, roots map[string]string) (map[string]any, error) {
	for _, key := range []string{signing.RootsFulcioKey, signing.RootsRekorKey, signing.RootsCTLogKey} {
		if strings.TrimSpace(roots[key]) == "" {
			return nil, fmt.Errorf("trust anchor %q is missing or empty", key)
		}
	}

	fulcioRoot := roots[signing.RootsFulcioKey]
	subject, err := certSubject(fulcioRoot)
	if err != nil {
		return nil, fmt.Errorf("trust anchor %q: %w", signing.RootsFulcioKey, err)
	}

	return map[string]any{
		"sigstoreKeys": map[string]any{
			"certificateAuthorities": []any{
				map[string]any{
					"subject":   subject,
					"uri":       endpoints.FulcioURL,
					"certChain": encode(fulcioRoot),
				},
			},
			"tLogs":  []any{transparencyLog(endpoints.RekorURL, roots[signing.RootsRekorKey])},
			"ctLogs": []any{transparencyLog(endpoints.CTLogURL, roots[signing.RootsCTLogKey])},
		},
	}, nil
}

func transparencyLog(baseURL, publicKeyPEM string) map[string]any {
	return map[string]any{
		"baseURL":       baseURL,
		"hashAlgorithm": hashAlgorithm,
		"publicKey":     encode(publicKeyPEM),
	}
}

// certSubject reads the distinguished name policy-controller requires on a
// certificate authority from the CA cert itself. Both fields are mandatory
// there, so each falls back to the other.
func certSubject(certPEM string) (map[string]any, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	commonName := cert.Subject.CommonName
	organization := strings.Join(cert.Subject.Organization, ",")
	if organization == "" {
		organization = commonName
	}
	if commonName == "" {
		commonName = organization
	}
	if commonName == "" {
		return nil, fmt.Errorf("certificate subject has neither organization nor common name")
	}
	return map[string]any{"organization": organization, "commonName": commonName}, nil
}

// encode renders PEM as policy-controller expects byte fields: base64.
func encode(pemData string) string {
	return base64.StdEncoding.EncodeToString([]byte(pemData))
}
