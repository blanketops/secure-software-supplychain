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
package events

import (
	"context"
	"fmt"

	triggersv1beta1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

const (
	eventListenerName = "secure-software-supplychain-listener"
	eventListenerPort = 8080
	ingressName       = "secure-software-supplychain-eventlistener-ingress"
	ingressClass      = "nginx"
)

// EnsureEventListener ensures the Tekton EventListener and its Ingress exist
// for the given SupplyChain. One EventListener per namespace, shared across
// all SupplyChains. Each SupplyChain gets its own named trigger entry.
//
// The Ingress host is sourced from sc.Spec.WebhookHost — set this to your
// public hostname (e.g. a Tailscale Funnel URL) so GitHub can reach the
// EventListener without port-forwarding or smee.io.
//
// Traffic flow:
//
//	GitHub → sc.Spec.WebhookHost → ingress-nginx → el-<name>:8080 → EventListener
func EnsureEventListener(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	sc *supplyv1alpha1.SupplyChain,
	serviceAccountName string,
) error {
	namespace := sc.Namespace
	supplyChainName := sc.Name

	// ── EventListener ─────────────────────────────────────────────────────
	var existing triggersv1beta1.EventListener
	err := c.Get(ctx, client.ObjectKey{Name: eventListenerName, Namespace: namespace}, &existing)
	if apierrors.IsNotFound(err) {
		el := buildEventListener(eventListenerName, namespace, supplyChainName, serviceAccountName)
		if err := controllerutil.SetControllerReference(sc, el, scheme); err != nil {
			return fmt.Errorf("setting EventListener owner: %w", err)
		}
		if err := c.Create(ctx, el); err != nil {
			return fmt.Errorf("creating EventListener: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("fetching EventListener: %w", err)
	} else {
		// Add trigger for this SupplyChain if not already present.
		triggerName := fmt.Sprintf("trigger-%s", supplyChainName)
		found := false
		for _, t := range existing.Spec.Triggers {
			if t.Name == triggerName {
				found = true
				break
			}
		}
		if !found {
			existing.Spec.Triggers = append(existing.Spec.Triggers,
				buildTrigger(triggerName, supplyChainName),
			)
			if err := c.Update(ctx, &existing); err != nil {
				return fmt.Errorf("updating EventListener: %w", err)
			}
		}
	}

	// ── Ingress ───────────────────────────────────────────────────────────
	if err := ensureIngress(ctx, c, scheme, sc); err != nil {
		return fmt.Errorf("ensuring EventListener ingress: %w", err)
	}

	return nil
}

// ensureIngress creates or updates the nginx Ingress for the EventListener.
// The host is sourced from sc.Spec.WebhookHost. If the host changes the
// ingress is updated so GitHub always routes to the correct endpoint.
func ensureIngress(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	sc *supplyv1alpha1.SupplyChain,
) error {
	host := sc.Spec.WebhookHost

	var existing networkingv1.Ingress
	err := c.Get(ctx, client.ObjectKey{Name: ingressName, Namespace: sc.Namespace}, &existing)
	if apierrors.IsNotFound(err) {
		ingress := buildIngress(sc.Namespace, host)
		if err := controllerutil.SetControllerReference(sc, ingress, scheme); err != nil {
			return fmt.Errorf("setting Ingress owner: %w", err)
		}
		return c.Create(ctx, ingress)
	}
	if err != nil {
		return fmt.Errorf("fetching Ingress: %w", err)
	}

	// Update host if it has changed.
	currentHost := ""
	if len(existing.Spec.Rules) > 0 {
		currentHost = existing.Spec.Rules[0].Host
	}
	if currentHost != host {
		existing.Spec.Rules = buildIngressRules(host)
		if err := c.Update(ctx, &existing); err != nil {
			return fmt.Errorf("updating Ingress host: %w", err)
		}
	}

	return nil
}

// buildIngress constructs the nginx Ingress for the EventListener service.
func buildIngress(namespace, host string) *networkingv1.Ingress {
	ingressClassName := ingressClass

	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingressName,
			Namespace: namespace,
			Labels: map[string]string{
				"blanketops.dev/managed":   "true",
				"blanketops.dev/component": "supply-chain-triggers",
			},
			Annotations: map[string]string{
				// EventListener speaks plain HTTP — no SSL redirect.
				"nginx.ingress.kubernetes.io/ssl-redirect": "false",
				// Preserve Host header for GitHub webhook signature validation.
				"nginx.ingress.kubernetes.io/preserve-host": "true",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClassName,
			Rules:            buildIngressRules(host),
		},
	}
}

// buildIngressRules returns the ingress rules for the given host.
// If host is empty, matches all requests (wildcard) — useful for local dev.
// In production, set sc.Spec.WebhookHost to the public Tailscale/DNS hostname.
func buildIngressRules(host string) []networkingv1.IngressRule {
	pathType := networkingv1.PathTypePrefix
	svcName := fmt.Sprintf("el-%s", eventListenerName)
	svcPort := int32(eventListenerPort)

	rule := networkingv1.IngressRule{
		IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{
					{
						Path:     "/",
						PathType: &pathType,
						Backend: networkingv1.IngressBackend{
							Service: &networkingv1.IngressServiceBackend{
								Name: svcName,
								Port: networkingv1.ServiceBackendPort{
									Number: svcPort,
								},
							},
						},
					},
				},
			},
		},
	}

	// Only set the host if one is provided — empty host matches everything.
	if host != "" {
		rule.Host = host
	}

	return []networkingv1.IngressRule{rule}
}

func buildEventListener(
	name, namespace, supplyChainName, serviceAccountName string,
) *triggersv1beta1.EventListener {
	return &triggersv1beta1.EventListener{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"blanketops.dev/managed":   "true",
				"blanketops.dev/component": "supply-chain-triggers",
			},
		},
		Spec: triggersv1beta1.EventListenerSpec{
			ServiceAccountName: serviceAccountName,
			Triggers: []triggersv1beta1.EventListenerTrigger{
				buildTrigger(fmt.Sprintf("trigger-%s", supplyChainName), supplyChainName),
			},
		},
	}
}

func ptrString(s string) *string {
	return &s
}

func buildTrigger(triggerName, supplyChainName string) triggersv1beta1.EventListenerTrigger {
	tbRef := fmt.Sprintf("secure-software-supplychain-github-binding-%s", supplyChainName)
	ttRef := fmt.Sprintf("secure-software-supplychain-imagebuild-template-%s", supplyChainName)

	return triggersv1beta1.EventListenerTrigger{
		Name: triggerName,
		Interceptors: []*triggersv1beta1.TriggerInterceptor{
			{
				Name: ptrString("github-push-filter"),
				Ref: triggersv1beta1.InterceptorRef{
					Name: "github",
					Kind: triggersv1beta1.ClusterInterceptorKind,
				},
				Params: []triggersv1beta1.InterceptorParams{
					{
						Name:  "eventTypes",
						Value: apiextensionsv1.JSON{Raw: []byte(`["push"]`)},
					},
				},
			},
			{
				Name: ptrString("cel-extract-fields"),
				Ref: triggersv1beta1.InterceptorRef{
					Name: "cel",
					Kind: triggersv1beta1.ClusterInterceptorKind,
				},
				Params: []triggersv1beta1.InterceptorParams{
					{
						Name:  "filter",
						Value: apiextensionsv1.JSON{Raw: []byte(`"body.ref.startsWith('refs/heads/')"`)},
					},
					{
						Name: "overlays",
						Value: apiextensionsv1.JSON{Raw: []byte(`[
							{"key": "branch_name", "expression": "body.ref.split('/')[2]"},
							{"key": "short_sha",   "expression": "body.after.truncate(7)"}
						]`)},
					},
				},
			},
		},
		Bindings: []*triggersv1beta1.TriggerSpecBinding{
			{
				Ref:  tbRef,
				Kind: triggersv1beta1.NamespacedTriggerBindingKind,
			},
		},
		Template: &triggersv1beta1.EventListenerTemplate{
			Ref: &ttRef,
		},
	}
}
