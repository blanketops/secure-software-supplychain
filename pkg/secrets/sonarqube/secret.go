package secrets

import (
	"context"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

type SonarQubeSecretReconciler struct {
	Client client.Client
	Log    logr.Logger
}

func NewSonarQubeSecretReconciler(
	c client.Client,
	log logr.Logger,
) *SonarQubeSecretReconciler {
	return &SonarQubeSecretReconciler{
		Client: c,
		Log:    log,
	}
}

func (r *SonarQubeSecretReconciler) Reconcile(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
) error {
	if sc.Spec.Steps.SonarQube == nil {
		return nil
	}

	secretName := sc.Spec.Steps.SonarQube.TokenSecretRef
	if secretName == "" {
		return nil
	}

	namespace := ib.Namespace

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
					"blanketops.dev/purpose":      "sonarqube",
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
						"type": "Opaque",
					},
				},
				"data": []any{
					map[string]any{
						// Tekton sonarqube task reads env var from secret key "token"
						"secretKey": "token",
						"remoteRef": map[string]any{
							"key": "/supplychain/sonarqube/token",
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
		"Creating ExternalSecret for SonarQube token",
		"supply-chain", sc.Name,
		"image-build", ib.Name,
		"secret", secretName,
	)

	return r.Client.Create(ctx, desired)
}
