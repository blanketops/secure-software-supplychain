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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EnsureTriggerBinding ensures the TriggerBinding exists for the given
// SupplyChain. Extracts fields from the GitHub push payload and maps
// them to parameters consumed by the TriggerTemplate.
func EnsureTriggerBinding(
	ctx context.Context,
	c client.Client,
	namespace string,
	supplyChainName string,
) error {
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
		return c.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("fetching TriggerBinding: %w", err)
	}
	existing.Spec = desired.Spec
	return c.Update(ctx, &existing)
}
