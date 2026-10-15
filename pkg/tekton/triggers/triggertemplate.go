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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	supplyv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
)

// EnsureTriggerTemplate ensures the TriggerTemplate exists for the given
// SupplyChain. Creates an ImageBuild CR when triggered by a GitHub push.
//
// ImageBuild name: <supplychain>-<branch>-<full-sha>
// Deterministic — idempotent on replay, one build per commit.
//
// Note: Kubernetes label values cannot contain '/' so repo-full-name
// (e.g. "your-org/your-app") lives in annotations only.
func EnsureTriggerTemplate(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	sc *supplyv1alpha1.SupplyChain,
) error {
	namespace, supplyChainName := sc.Namespace, sc.Name
	name := fmt.Sprintf("secure-software-supplychain-imagebuild-template-%s", supplyChainName)

	imageBuildTemplate := map[string]any{
		"apiVersion": "supplychain.blanketops.dev/v1alpha1",
		"kind":       "ImageBuild",
		"metadata": map[string]any{
			"name":      fmt.Sprintf("%s-$(tt.params.git-revision)-$(tt.params.git-commit-sha)", supplyChainName),
			"namespace": namespace,
			"labels": map[string]any{
				// Label values: alphanumeric + '-' + '_' + '.' only.
				// repo-full-name contains '/' → annotation instead.
				"blanketops.dev/supply-chain": supplyChainName,
				"blanketops.dev/triggered-by": "github-push",
				"blanketops.dev/git-revision": "$(tt.params.git-revision)",
			},
			"annotations": map[string]any{
				// Annotations have no character restrictions.
				"blanketops.dev/git-commit-sha": "$(tt.params.git-commit-sha)",
				"blanketops.dev/git-repo-url":   "$(tt.params.git-repo-url)",
				"blanketops.dev/repo-full-name": "$(tt.params.repo-full-name)",
			},
		},
		"spec": map[string]any{
			"supplyChainRef": map[string]any{
				"name": supplyChainName,
			},
			"gitRef": map[string]any{
				"url":      "$(tt.params.git-repo-url)",
				"revision": "$(tt.params.git-revision)",
			},
			// Full commit SHA as image tag — every image traceable to exact commit.
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
				{Name: "git-repo-url", Description: "SSH clone URL of the repository"},
				{Name: "git-revision", Description: "Branch name that was pushed to"},
				{Name: "git-commit-sha", Description: "Full SHA of the commit"},
				{Name: "short-sha", Description: "First 7 chars of commit SHA"},
				{Name: "repo-full-name", Description: "GitHub repo full name e.g. org/repo"},
			},
			ResourceTemplates: []triggersv1beta1.TriggerResourceTemplate{
				{
					RawExtension: runtime.RawExtension{Raw: raw},
				},
			},
		},
	}

	var existing triggersv1beta1.TriggerTemplate
	err = c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &existing)
	if apierrors.IsNotFound(err) {
		// It is this SupplyChain's alone, and is removed with it.
		if err := controllerutil.SetControllerReference(sc, desired, scheme); err != nil {
			return err
		}
		return c.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("fetching TriggerTemplate: %w", err)
	}

	existing.Spec = desired.Spec
	// One made before it had an owner is given one now.
	if err := controllerutil.SetControllerReference(sc, &existing, scheme); err != nil {
		return err
	}
	return c.Update(ctx, &existing)
}
