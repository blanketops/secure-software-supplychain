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

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	rekorNamespace        = "rekor-system"
	rekorSigningKeySecret = "rekor-signing-key"
	rekorSigningKeyFile   = "key.pem"
)

// ensureRekorSigningKey gives Rekor a signing key that outlives its pod.
//
// Rekor signs every log entry it returns; verifiers check that signature
// against the public key in the trust anchors. The key is created once and
// never replaced: a new key would invalidate every signature made before it.
func (i *Installer) ensureRekorSigningKey(ctx context.Context) error {
	namespaces := i.dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"})
	ns := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": rekorNamespace},
	}}
	if _, err := namespaces.Create(ctx, ns, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating namespace %s: %w", rekorNamespace, err)
	}

	secrets := i.dynamic.
		Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).
		Namespace(rekorNamespace)
	_, err := secrets.Get(ctx, rekorSigningKeySecret, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("reading secret %s/%s: %w", rekorNamespace, rekorSigningKeySecret, err)
	}

	keyPEM, err := newRekorSigningKey()
	if err != nil {
		return err
	}
	secret := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      rekorSigningKeySecret,
			"namespace": rekorNamespace,
			"labels":    map[string]any{"blanketops.dev/managed": "true"},
		},
		"type":       "Opaque",
		"stringData": map[string]any{rekorSigningKeyFile: string(keyPEM)},
	}}
	if _, err := secrets.Create(ctx, secret, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating secret %s/%s: %w", rekorNamespace, rekorSigningKeySecret, err)
	}
	return nil
}

// newRekorSigningKey returns a new ECDSA P-256 private key, PEM-encoded PKCS#8.
func newRekorSigningKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Rekor signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding Rekor signing key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
