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

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/store"
)

type GitSSHSecretReconciler struct {
	Client client.Client
	Log    logr.Logger
}

func NewGitSSHSecretReconciler(
	c client.Client,
	log logr.Logger,
) *GitSSHSecretReconciler {
	return &GitSSHSecretReconciler{
		Client: c,
		Log:    log,
	}
}

func (r *GitSSHSecretReconciler) Reconcile(
	ctx context.Context,
	sc *supplyv1alpha1.SupplyChain,
	ib *supplyv1alpha1.ImageBuild,
) error {

	secretName := sc.Spec.Image.CloneSecretRef
	namespace := ib.Namespace

	// -------------------------------------------------------------------------
	// Desired ExternalSecret (aligned with Tekton git-clone workspace model)
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
					"blanketops.dev/purpose":      "git-ssh",
					"blanketops.dev/supply-chain": sc.Name,
					"blanketops.dev/image-build":  ib.LabelValue(),
				},
			},
			"spec": map[string]any{
				"refreshInterval": store.RefreshInterval,
				"secretStoreRef":  store.Ref(),
				"target": map[string]any{
					"name": secretName,
					"template": map[string]any{
						"type": "Opaque",
					},
				},
				"data": []any{
					map[string]any{
						"secretKey": "id_rsa",
						"remoteRef": store.RemoteRef(store.Git, store.GitPrivateKey),
					},
					map[string]any{
						"secretKey": "known_hosts",
						"remoteRef": store.RemoteRef(store.Git, store.GitKnownHosts),
					},
					map[string]any{
						"secretKey": "config",
						"remoteRef": store.RemoteRef(store.Git, store.GitSSHConfig),
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

	outcome, err := store.Apply(ctx, r.Client, desired)
	if err != nil {
		return err
	}
	if outcome != store.Unchanged {
		r.Log.Info("Applied ExternalSecret for Git SSH",
			"outcome", outcome, "supply-chain", sc.Name, "image-build", ib.Name, "secret", secretName)
	}
	return nil
}
