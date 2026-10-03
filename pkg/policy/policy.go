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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
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
	TrustRoot          *unstructured.Unstructured
	ClusterImagePolicy *unstructured.Unstructured
	// Images are the globs the ClusterImagePolicy applies to.
	Images []string
	// Identity is the certificate subject the images must be signed by.
	Identity string
}

// ResourceName is the name shared by the TrustRoot and ClusterImagePolicy of a
// SupplyChainPolicy. Both are cluster-scoped, so the namespace is part of it.
func ResourceName(scp *supplyv1alpha1.SupplyChainPolicy) string {
	return scp.Namespace + "-" + scp.Name
}

// Render builds the TrustRoot and ClusterImagePolicy for scp from the
// SupplyChain it references and the trust anchors in roots (the data of
// signing.RootsConfigMap). The sigstore endpoints and keys are stated once, in
// the TrustRoot; the ClusterImagePolicy only points at it.
func Render(
	scp *supplyv1alpha1.SupplyChainPolicy,
	sc *supplyv1alpha1.SupplyChain,
	roots map[string]string,
) (*Rendered, error) {
	name := ResourceName(scp)
	endpoints := signing.EndpointsFor(sc)

	trustRootSpec, err := trustRootSpec(endpoints, roots)
	if err != nil {
		return nil, err
	}

	serviceAccount := sc.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	identity := signing.ServiceAccountIdentity(sc.Namespace, serviceAccount)
	images := []string{ImageGlob(sc)}

	mode := scp.Spec.Mode
	if mode == "" {
		mode = "enforce"
	}

	globs := make([]any, 0, len(images))
	for _, glob := range images {
		globs = append(globs, map[string]any{"glob": glob})
	}
	policySpec := map[string]any{
		"mode":   mode,
		"images": globs,
		"authorities": []any{
			map[string]any{
				"name": "supply-chain",
				"keyless": map[string]any{
					"url":          endpoints.FulcioURL,
					"trustRootRef": name,
					"identities": []any{
						map[string]any{
							"issuer":  signing.KubernetesOIDCIssuer,
							"subject": identity,
						},
					},
				},
				"ctlog": map[string]any{
					"url":          endpoints.RekorURL,
					"trustRootRef": name,
				},
			},
		},
	}

	return &Rendered{
		TrustRoot:          newObject(TrustRootGVK, name, scp, trustRootSpec),
		ClusterImagePolicy: newObject(ClusterImagePolicyGVK, name, scp, policySpec),
		Images:             images,
		Identity:           identity,
	}, nil
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
			return nil, fmt.Errorf("trust anchor %q is missing from ConfigMap %q", key, signing.RootsConfigMap)
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
