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
	"bytes"
	"context"
	"fmt"
	"path"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/log"

	manifests "github.com/blanketops/secure-software-supplychain"
	supplyv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
)

// catalogTaskFiles are the Tekton catalog Tasks the pipeline runs (git-clone,
// buildah, trivy-scanner), as embedded from dependencies/tekton/task. The
// installer applies them to default only; a SupplyChain anywhere else gets
// them from the operator.
var catalogTaskFiles = []string{"gitclone.yaml", "buildah.yaml", "trivyscanner.yaml"}

const catalogTaskDir = "dependencies/tekton/task"

// catalogTasks reads the catalog Tasks, placed in namespace.
func catalogTasks(namespace string) ([]tektonv1.Task, error) {
	tasks := make([]tektonv1.Task, 0, len(catalogTaskFiles))
	for _, file := range catalogTaskFiles {
		data, err := manifests.TektonTasks.ReadFile(path.Join(catalogTaskDir, file))
		if err != nil {
			return nil, fmt.Errorf("reading the catalog Task %s: %w", file, err)
		}
		var task tektonv1.Task
		if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), len(data)).Decode(&task); err != nil {
			return nil, fmt.Errorf("parsing the catalog Task %s: %w", file, err)
		}
		task.Namespace = namespace
		tasks = append(tasks, task)
	}
	return tasks, nil
}

// reconcileCatalogTasks keeps the catalog Tasks in the SupplyChain's
// namespace, shared by every SupplyChain there and removed with the last of
// them. A Task of the same name the operator did not create, such as the
// installer's in default, is used as it is.
func (r *SupplyChainReconciler) reconcileCatalogTasks(ctx context.Context, sc *supplyv1alpha1.SupplyChain) error {
	desired, err := catalogTasks(sc.Namespace)
	if err != nil {
		return err
	}
	for i := range desired {
		want := &desired[i]
		var task tektonv1.Task
		err := r.Get(ctx, types.NamespacedName{Namespace: want.Namespace, Name: want.Name}, &task)
		if apierrors.IsNotFound(err) {
			labels := want.GetLabels()
			if labels == nil {
				labels = map[string]string{}
			}
			labels[managedLabel] = "true"
			want.SetLabels(labels)
			if _, err := shareWith(sc, want, r.Scheme); err != nil {
				return err
			}
			if err := r.Create(ctx, want); err != nil {
				return fmt.Errorf("creating Task %q: %w", want.Name, err)
			}
			log.FromContext(ctx).Info("task reconciled", "task", want.Name, "result", "created")
			continue
		}
		if err != nil {
			return fmt.Errorf("reading Task %q: %w", want.Name, err)
		}
		if !managed(&task) {
			continue
		}
		changed, err := shareWith(sc, &task, r.Scheme)
		if err != nil {
			return err
		}
		if !equality.Semantic.DeepEqual(task.Spec, want.Spec) {
			task.Spec = want.Spec
			changed = true
		}
		if changed {
			if err := r.Update(ctx, &task); err != nil {
				return fmt.Errorf("updating Task %q: %w", want.Name, err)
			}
		}
	}
	return nil
}
