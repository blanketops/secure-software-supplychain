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
	"strings"
	"testing"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
)

// Every Task the operator supplies runs images pinned by digest: its own
// Tasks, and the catalog Tasks, whose images are parameter defaults.
func TestEveryTaskImageIsPinnedByDigest(t *testing.T) {
	catalog, err := catalogTasks("any")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, task := range append(customTasks("any"), catalog...) {
		params := map[string]string{}
		for _, p := range task.Spec.Params {
			if p.Default != nil && p.Default.Type == tektonv1.ParamTypeString {
				params[p.Name] = p.Default.StringVal
			}
		}
		for _, step := range task.Spec.Steps {
			image := step.Image
			// An image given as a parameter is checked through its default.
			if name, ok := strings.CutPrefix(image, "$(params."); ok {
				name = strings.TrimSuffix(name, ")")
				image = params[name]
			}
			checked++
			if !strings.Contains(image, "@sha256:") {
				t.Errorf("Task %s, step %s: image %q is not pinned by digest", task.Name, step.Name, image)
			}
		}
	}
	if checked < 6 {
		t.Fatalf("checked %d step images; expected the steps of all six Tasks", checked)
	}
}
