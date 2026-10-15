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
package triggers

import (
	"context"
	"fmt"

	triggersv1beta1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
)

// EnsureTriggerBinding ensures the TriggerBinding exists for the given
// SupplyChain. Extracts fields from the GitHub push payload and maps
// them to parameters consumed by the TriggerTemplate.
func EnsureTriggerBinding(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	sc *supplyv1alpha1.SupplyChain,
) error {
	namespace, supplyChainName := sc.Namespace, sc.Name
	name := fmt.Sprintf("secure-software-supplychain-github-binding-%s", supplyChainName)

	desired := &triggersv1beta1.TriggerBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"blanketops.dev/managed":      "true",
				"blanketops.dev/supply-chain": supplyChainName,
			},
		},
		Spec: triggersv1beta1.TriggerBindingSpec{
			Params: []triggersv1beta1.Param{
				{
					// SSH clone URL — maps to gitRef.url in ImageBuild.
					Name:  "git-repo-url",
					Value: "$(body.repository.ssh_url)",
				},
				{
					// Branch name from CEL overlay — maps to gitRef.revision.
					Name:  "git-revision",
					Value: "$(extensions.branch_name)",
				},
				{
					// Full commit SHA — used as imageTag for traceability.
					Name:  "git-commit-sha",
					Value: "$(body.after)",
				},
				{
					// Short SHA from CEL overlay — used in ImageBuild name.
					Name:  "short-sha",
					Value: "$(extensions.short_sha)",
				},
				{
					// GitHub repo full name e.g. "your-org/your-app"
					Name:  "repo-full-name",
					Value: "$(body.repository.full_name)",
				},
			},
		},
	}

	var existing triggersv1beta1.TriggerBinding
	err := c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &existing)
	if apierrors.IsNotFound(err) {
		// It is this SupplyChain's alone, and is removed with it.
		if err := controllerutil.SetControllerReference(sc, desired, scheme); err != nil {
			return err
		}
		return c.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("fetching TriggerBinding: %w", err)
	}
	existing.Spec = desired.Spec
	// One made before it had an owner is given one now.
	if err := controllerutil.SetControllerReference(sc, &existing, scheme); err != nil {
		return err
	}
	return c.Update(ctx, &existing)
}
