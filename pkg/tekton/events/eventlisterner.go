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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EnsureEventListener ensures the Tekton EventListener exists for the given
// SupplyChain. One EventListener per namespace, shared across all SupplyChains.
// Each SupplyChain gets its own named trigger entry.
func EnsureEventListener(
	ctx context.Context,
	c client.Client,
	namespace string,
	supplyChainName string,
	serviceAccountName string,
) error {
	name := "secure-software-supplychain-listener"

	var existing triggersv1beta1.EventListener
	err := c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &existing)
	if apierrors.IsNotFound(err) {
		el := buildEventListener(name, namespace, supplyChainName, serviceAccountName)
		return c.Create(ctx, el)
	}
	if err != nil {
		return fmt.Errorf("fetching EventListener: %w", err)
	}

	// Add trigger for this SupplyChain if not already present.
	triggerName := fmt.Sprintf("trigger-%s", supplyChainName)
	for _, t := range existing.Spec.Triggers {
		if t.Name == triggerName {
			return nil
		}
	}
	existing.Spec.Triggers = append(existing.Spec.Triggers,
		buildTrigger(triggerName, supplyChainName),
	)
	return c.Update(ctx, &existing)
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
						Value: apiextensionsv1.JSON{Raw: []byte(`"body.ref.startsWith('refs/heads/')"`)}},
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
