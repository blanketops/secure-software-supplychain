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
	"encoding/base64"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	ingressNamespace       = "ingress-nginx"
	ingressAdmissionName   = "ingress-nginx-admission"
	ingressAdmissionCAKey  = "ca"
	ingressAdmissionCAPath = "caBundle"
)

// ensureIngressWebhookCA writes the admission webhook's CA into its
// ValidatingWebhookConfiguration.
//
// The ingress-nginx manifest ships the configuration without a CA and relies
// on a one-off Job to fill it in. Applying the manifest again clears the CA,
// and the Job, having completed, does not run again; from then on the API
// server rejects every Ingress because it cannot verify the webhook.
func (i *Installer) ensureIngressWebhookCA(ctx context.Context) error {
	if err := i.waitForSecret(ctx, ingressNamespace, ingressAdmissionName, readyTimeout); err != nil {
		return err
	}
	ca, err := i.readSecretKey(ctx, ingressNamespace, ingressAdmissionName, ingressAdmissionCAKey)
	if err != nil {
		return fmt.Errorf("reading the ingress admission CA: %w", err)
	}
	bundle := base64.StdEncoding.EncodeToString(ca)

	configs := i.dynamic.Resource(schema.GroupVersionResource{
		Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations",
	})
	config, err := configs.Get(ctx, ingressAdmissionName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading ValidatingWebhookConfiguration %s: %w", ingressAdmissionName, err)
	}
	webhooks, _ := config.Object["webhooks"].([]any)
	changed := false
	for _, w := range webhooks {
		webhook, ok := w.(map[string]any)
		if !ok {
			continue
		}
		clientConfig, _ := webhook["clientConfig"].(map[string]any)
		if clientConfig == nil {
			clientConfig = map[string]any{}
			webhook["clientConfig"] = clientConfig
		}
		if clientConfig[ingressAdmissionCAPath] != bundle {
			clientConfig[ingressAdmissionCAPath] = bundle
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if _, err := configs.Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating ValidatingWebhookConfiguration %s: %w", ingressAdmissionName, err)
	}
	return nil
}
