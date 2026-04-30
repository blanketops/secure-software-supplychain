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
	"encoding/json"
	"fmt"

	triggersv1beta1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EnsureTriggerTemplate ensures the TriggerTemplate exists for the given
// SupplyChain. The template creates an ImageBuild CR when triggered by
// a GitHub push event — wiring the event payload directly into the
// operator's reconciliation loop.
//
// The ImageBuild name is deterministic:
//
//	<supplychain-name>-$(tt.params.git-revision)-$(tt.params.git-commit-sha[0:7])
//
// This ensures one ImageBuild per commit per branch — idempotent on replay.
func EnsureTriggerTemplate(
	ctx context.Context,
	c client.Client,
	namespace string,
	supplyChainName string,
) error {
	name := fmt.Sprintf("blanketops-imagebuild-template-%s", supplyChainName)

	// The ImageBuild resource template — populated at trigger time.
	imageBuildTemplate := map[string]interface{}{
		"apiVersion": "supplychain.blanketops.dev/v1alpha1",
		"kind":       "ImageBuild",
		"metadata": map[string]interface{}{
			"name":      fmt.Sprintf("%s-$(tt.params.git-revision)-$(tt.params.git-commit-sha)", supplyChainName),
			"namespace": namespace,
			"labels": map[string]string{
				"blanketops.dev/supply-chain": supplyChainName,
				"blanketops.dev/triggered-by": "github-push",
				"blanketops.dev/git-revision": "$(tt.params.git-revision)",
				"blanketops.dev/repo":         "$(tt.params.repo-full-name)",
			},
			"annotations": map[string]string{
				"blanketops.dev/git-commit-sha": "$(tt.params.git-commit-sha)",
				"blanketops.dev/git-repo-url":   "$(tt.params.git-repo-url)",
			},
		},
		"spec": map[string]interface{}{
			"supplyChainRef": map[string]interface{}{
				"name": supplyChainName,
			},
			"gitRef": map[string]interface{}{
				// SSH URL from GitHub push payload — e.g. git@github.com:org/repo.git
				"url": "$(tt.params.git-repo-url)",
				// Branch name — e.g. "main", "master"
				"revision": "$(tt.params.git-revision)",
			},
			// Full commit SHA used as the image tag — enables traceability
			// from image back to exact commit that produced it.
			"imageTag": "$(tt.params.git-commit-sha)",
		},
	}

	raw, err := json.Marshal(imageBuildTemplate)
	if err != nil {
		return fmt.Errorf("marshalling ImageBuild template: %w", err)
	}

	desired := &triggersv1beta1.TriggerTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"blanketops.dev/managed":      "true",
				"blanketops.dev/supply-chain": supplyChainName,
			},
		},
		Spec: triggersv1beta1.TriggerTemplateSpec{
			Params: []triggersv1beta1.ParamSpec{
				{
					Name:        "git-repo-url",
					Description: "SSH clone URL of the repository",
				},
				{
					Name:        "git-revision",
					Description: "Branch name that was pushed to",
				},
				{
					Name:        "git-commit-sha",
					Description: "Full SHA of the commit that triggered the push",
				},
				{
					Name:        "repo-full-name",
					Description: "GitHub repository full name e.g. org/repo",
				},
			},
			ResourceTemplates: []triggersv1beta1.TriggerResourceTemplate{
				{
					RawExtension: runtime.RawExtension{
						Raw: raw,
					},
				},
			},
		},
	}

	var existing triggersv1beta1.TriggerTemplate
	err = c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &existing)
	if apierrors.IsNotFound(err) {
		return c.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("fetching TriggerTemplate: %w", err)
	}

	existing.Spec = desired.Spec
	return c.Update(ctx, &existing)
}
