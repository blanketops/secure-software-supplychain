package secrets

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/ntlaletsi70/blanketops-environments-supply-chain/api/v1alpha1"
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
		// No registry secret requested
		return nil
	}

	secretName := sc.Spec.Image.RegistrySecretRef
	if secretName == "" {
		return nil
	}

	namespace := ib.Namespace

	// tekton.dev/docker-0 must carry the full https:// prefix so Tekton's
	// credential initializer wires the secret to the correct registry host.
	registryAnnotation := fmt.Sprintf("https://%s", sc.Spec.Image.Registry)

	// -------------------------------------------------------------------------
	// Desired ExternalSecret (UNSTRUCTURED)
	// -------------------------------------------------------------------------
	desired := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "external-secrets.io/v1",
			"kind":       "ExternalSecret",
			"metadata": map[string]any{
				"name":      secretName,
				"namespace": namespace,
				"labels": map[string]any{
					"blanketops.dev/managed":      "true",
					"blanketops.dev/purpose":      "registry",
					"blanketops.dev/supply-chain": sc.Name,
					"blanketops.dev/image-build":  ib.Name,
				},
			},
			"spec": map[string]any{
				"refreshInterval": "0s",
				"secretStoreRef": map[string]any{
					"name": "blanketops-supply-chain-store",
					"kind": "ClusterSecretStore",
				},
				"target": map[string]any{
					"name": secretName,
					"template": map[string]any{
						// Opaque type — key is config.json, mounted by the Tekton
						// kaniko Task into /kaniko/.docker/config.json via the
						// dockerconfig workspace. Kaniko reads it from there directly.
						"type": "Opaque",
						// tekton.dev/docker-0 wires this secret to the registry host
						// in Tekton's credential initializer so Kaniko can push.
						"metadata": map[string]any{
							"annotations": map[string]any{
								"tekton.dev/docker-0": registryAnnotation,
							},
						},
					},
				},
				"data": []any{
					map[string]any{
						"secretKey": "config.json",
						"remoteRef": map[string]any{
							"key": "/supplychain/registry/config",
						},
					},
				},
			},
		},
	}

	// -------------------------------------------------------------------------
	// Ownership (ImageBuild → ExternalSecret)
	// -------------------------------------------------------------------------
	if err := controllerutil.SetControllerReference(
		ib,
		desired,
		r.Client.Scheme(),
	); err != nil {
		return err
	}

	// -------------------------------------------------------------------------
	// Fetch existing (CREATE-ONLY semantics — existence is enough)
	// -------------------------------------------------------------------------
	var existing unstructured.Unstructured
	existing.SetGroupVersionKind(desired.GroupVersionKind())

	err := r.Client.Get(
		ctx,
		client.ObjectKeyFromObject(desired),
		&existing,
	)

	if err == nil {
		return nil
	}

	if !apierrors.IsNotFound(err) {
		return err
	}

	r.Log.Info(
		"Creating ExternalSecret for registry credentials",
		"supply-chain", sc.Name,
		"image-build", ib.Name,
		"secret", secretName,
	)

	return r.Client.Create(ctx, desired)
}
