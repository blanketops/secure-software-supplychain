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

package pipeline

import (
	"strings"
	"testing"
)

// A supply chain that verifies what it builds has to run exactly the tools it
// was tested with: every image of the pipeline's own steps is pinned by
// digest, so a moved tag cannot change what runs.
func TestEveryStepImageIsPinnedByDigest(t *testing.T) {
	pr := testPipelineRun(t)
	checked := 0
	for _, task := range pr.Spec.PipelineSpec.Tasks {
		if task.TaskSpec == nil {
			continue // a Task run by name; its images are checked where it is defined
		}
		for _, step := range task.TaskSpec.Steps {
			checked++
			if !strings.Contains(step.Image, "@sha256:") {
				t.Errorf("task %s, step %s: image %q is not pinned by digest", task.Name, step.Name, step.Image)
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no inline steps to check; the pipeline's shape changed")
	}
}
