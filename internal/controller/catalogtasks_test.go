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

package controller

import (
	"context"
	"strings"
	"testing"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	supplyv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	"github.com/blanketops/secure-software-supplychain/pkg/tekton/pipeline"
)

// The pipeline runs git-clone, buildah and trivy-scanner by name from the
// SupplyChain's namespace. The installer puts them in default only, so in
// any other namespace, the operator's own included, the operator supplies
// them; a build there otherwise fails with "Couldn't retrieve Task".
func TestTheCatalogTasksFollowASupplyChainToItsNamespace(t *testing.T) {
	const ns = "secure-software-supply-chain-system"
	ctx := context.Background()
	scheme := ownershipScheme(t)
	first := &supplyv1alpha1.SupplyChain{ObjectMeta: metav1.ObjectMeta{Name: "your-app", Namespace: ns, UID: "first"}}
	second := &supplyv1alpha1.SupplyChain{ObjectMeta: metav1.ObjectMeta{Name: "your-other-app", Namespace: ns, UID: "second"}}

	wantNames := []string{"git-clone", "buildah", "trivy-scanner"}
	embedded, err := catalogTasks(ns)
	if err != nil {
		t.Fatal(err)
	}
	if len(embedded) != len(wantNames) {
		t.Fatalf("catalog Tasks: got %d, want %d", len(embedded), len(wantNames))
	}

	t.Run("created in the namespace and shared", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &SupplyChainReconciler{Client: c, Scheme: scheme}
		for _, sc := range []*supplyv1alpha1.SupplyChain{first, second, first} {
			if err := r.reconcileCatalogTasks(ctx, sc); err != nil {
				t.Fatal(err)
			}
		}
		for i, name := range wantNames {
			var task tektonv1.Task
			if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &task); err != nil {
				t.Fatalf("Task %s not in %s: %v", name, ns, err)
			}
			if !managed(&task) || ownerRef(&task, first.UID) == nil || ownerRef(&task, second.UID) == nil ||
				len(task.OwnerReferences) != 2 {
				t.Errorf("Task %s: want managed, owned once by each SupplyChain; labels %v, owners %v",
					name, task.Labels, task.OwnerReferences)
			}
			if len(task.Spec.Steps) == 0 || len(task.Spec.Steps) != len(embedded[i].Spec.Steps) {
				t.Errorf("Task %s: %d steps, want the embedded definition's %d",
					name, len(task.Spec.Steps), len(embedded[i].Spec.Steps))
			}
		}
	})

	t.Run("a Task the operator did not create is left alone", func(t *testing.T) {
		theirs := &tektonv1.Task{
			ObjectMeta: metav1.ObjectMeta{Name: "git-clone", Namespace: ns},
			Spec:       tektonv1.TaskSpec{Description: "their own"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(theirs).Build()
		r := &SupplyChainReconciler{Client: c, Scheme: scheme}
		if err := r.reconcileCatalogTasks(ctx, first); err != nil {
			t.Fatal(err)
		}
		var task tektonv1.Task
		_ = c.Get(ctx, types.NamespacedName{Namespace: ns, Name: "git-clone"}, &task)
		if task.Spec.Description != "their own" || len(task.OwnerReferences) != 0 {
			t.Errorf("changed a Task the operator did not create: %q, owners %v",
				task.Spec.Description, task.OwnerReferences)
		}
	})
}

// The SBOM the sign task attests is written by trivy-scanner, from the same
// archive it scans, into the shared workspace under pipeline.SBOMFile.
func TestTrivyTaskWritesTheSBOM(t *testing.T) {
	tasks, err := catalogTasks("default")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		if task.Name != "trivy-scanner" {
			continue
		}
		script := task.Spec.Steps[0].Script
		for _, want := range []string{
			"--format cyclonedx",
			`--output "$(workspaces.manifest-dir.path)/` + pipeline.SBOMFile + `"`,
		} {
			if !strings.Contains(script, want) {
				t.Errorf("trivy-scanner script does not contain %s", want)
			}
		}
		return
	}
	t.Fatal("no trivy-scanner Task")
}
