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
package secrets

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/store"
)

type RegistrySecretReconciler struct {
	Client client.Client
	Log    logr.Logger
}

func NewRegistrySecretReconciler(
	c client.Client,
	log logr.Logger,
) *RegistrySecretReconciler {
	return &RegistrySecretReconciler{
		Client: c,
		Log:    log,
	}
}

func (r *RegistrySecretReconciler) Reconcile(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
) error {
	if sc.Spec.Image.RegistrySecretRef == "" {
		return nil
	}

	secretName := sc.Spec.Image.RegistrySecretRef
	namespace := ib.Namespace
	registryAnnotation := fmt.Sprintf("https://%s", sc.Spec.Image.Registry)

	// 1. Kaniko secret (Opaque, config.json key)
	if err := r.reconcileExternalSecret(ctx, sc, ib, kanikoSecretSpec{
		name:               secretName,
		namespace:          namespace,
		registryAnnotation: registryAnnotation,
	}); err != nil {
		return fmt.Errorf("kaniko registry secret: %w", err)
	}

	// 2. Chains secret (dockerconfigjson, .dockerconfigjson key)
	if err := r.reconcileExternalSecret(ctx, sc, ib, chainsSecretSpec{
		name:               ChainsSecretName(secretName),
		namespace:          namespace,
		registryAnnotation: registryAnnotation,
	}); err != nil {
		return fmt.Errorf("chains registry secret: %w", err)
	}

	return nil
}

// ChainsSecretName is the name of the image pull secret synced for Tekton
// Chains from a SupplyChain's registry secret.
func ChainsSecretName(registrySecret string) string {
	return registrySecret + "-chains"
}

// -------------------------------------------------------------------------
// Secret spec types
// -------------------------------------------------------------------------

type kanikoSecretSpec struct {
	name               string
	namespace          string
	registryAnnotation string
}

func (s kanikoSecretSpec) toUnstructured(sc *supplyv1alpha1.SupplyChain, ib *supplyv1alpha1.ImageBuild) *unstructured.Unstructured {
	return newExternalSecret(externalSecretParams{
		name:               s.name,
		namespace:          s.namespace,
		sc:                 sc,
		ib:                 ib,
		secretType:         "Opaque",
		secretKey:          "config.json",
		registryAnnotation: s.registryAnnotation,
	})
}

type chainsSecretSpec struct {
	name               string
	namespace          string
	registryAnnotation string
}

func (s chainsSecretSpec) toUnstructured(sc *supplyv1alpha1.SupplyChain, ib *supplyv1alpha1.ImageBuild) *unstructured.Unstructured {
	return newExternalSecret(externalSecretParams{
		name:               s.name,
		namespace:          s.namespace,
		sc:                 sc,
		ib:                 ib,
		secretType:         "kubernetes.io/dockerconfigjson",
		secretKey:          ".dockerconfigjson",
		registryAnnotation: s.registryAnnotation,
	})
}

// secretSpec is anything that can produce the desired ExternalSecret.
type secretSpec interface {
	toUnstructured(sc *supplyv1alpha1.SupplyChain, ib *supplyv1alpha1.ImageBuild) *unstructured.Unstructured
}

// -------------------------------------------------------------------------
// Shared reconcile logic
// -------------------------------------------------------------------------

func (r *RegistrySecretReconciler) reconcileExternalSecret(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
	spec secretSpec,
) error {
	desired := spec.toUnstructured(sc, ib)

	if err := controllerutil.SetControllerReference(
		ib,
		desired,
		r.Client.Scheme(),
	); err != nil {
		return err
	}

	outcome, err := store.Apply(ctx, r.Client, desired)
	if err != nil {
		return err
	}
	if outcome != store.Unchanged {
		r.Log.Info("Applied ExternalSecret for registry credentials",
			"outcome", outcome, "supply-chain", sc.Name, "image-build", ib.Name, "secret", desired.GetName())
	}
	return nil
}

// -------------------------------------------------------------------------
// ExternalSecret builder
// -------------------------------------------------------------------------

type externalSecretParams struct {
	name               string
	namespace          string
	sc                 *supplyv1alpha1.SupplyChain
	ib                 *supplyv1alpha1.ImageBuild
	secretType         string // "Opaque" or "kubernetes.io/dockerconfigjson"
	secretKey          string // "config.json" or ".dockerconfigjson"
	registryAnnotation string
}

func newExternalSecret(p externalSecretParams) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "external-secrets.io/v1",
			"kind":       "ExternalSecret",
			"metadata": map[string]any{
				"name":      p.name,
				"namespace": p.namespace,
				"labels": map[string]any{
					"blanketops.dev/managed":      "true",
					"blanketops.dev/purpose":      "registry",
					"blanketops.dev/supply-chain": p.sc.Name,
					"blanketops.dev/image-build":  p.ib.LabelValue(),
				},
			},
			"spec": map[string]any{
				"refreshInterval": store.RefreshInterval,
				"secretStoreRef":  store.Ref(),
				"target": map[string]any{
					"name": p.name,
					"template": map[string]any{
						"type": p.secretType,
						"metadata": map[string]any{
							"annotations": map[string]any{
								"tekton.dev/docker-0": p.registryAnnotation,
							},
						},
					},
				},
				"data": []any{
					map[string]any{
						"secretKey": p.secretKey,
						"remoteRef": store.RemoteRef(store.Registry, store.RegistryConfig),
					},
				},
			},
		},
	}
}
