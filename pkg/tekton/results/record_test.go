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
package results

import (
	"testing"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
)

func result(name, value string) tektonv1.TaskRunResult {
	return tektonv1.TaskRunResult{Name: name, Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: value}}
}

func taskRun(results ...tektonv1.TaskRunResult) tektonv1.TaskRun {
	return tektonv1.TaskRun{Status: tektonv1.TaskRunStatus{
		TaskRunStatusFields: tektonv1.TaskRunStatusFields{Results: results},
	}}
}

// A build stopped by the vulnerability gate publishes no pipeline results for
// the scan; the counts must still be recorded, from the TaskRun.
func TestFillFromTaskRunsRecordsWhyAGateFailed(t *testing.T) {
	run := &tektonv1.PipelineRun{}
	run.Status.Results = []tektonv1.PipelineRunResult{
		{Name: "commit", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "abc123"}},
	}
	got := ExtractAllResults(run)

	FillFromTaskRuns(got, []tektonv1.TaskRun{
		taskRun(result("commit", "from-taskrun"), result("url", "git@example.com:org/app.git")),
		taskRun(result("IMAGE_URL", "docker.io/org/app:tag"), result("IMAGE_DIGEST", "sha256:archive")),
		taskRun(result("TRIVY_SCAN_SUMMARY", "FAIL"), result("TRIVY_CRITICAL_COUNT", "26"), result("UNKNOWN", "x")),
	})

	if got.TrivyScanSummary != "FAIL" || got.TrivyCriticalCount != "26" {
		t.Errorf("scan results = %q/%q, want FAIL/26 from the TaskRun", got.TrivyScanSummary, got.TrivyCriticalCount)
	}
	if got.Commit != "abc123" {
		t.Errorf("Commit = %q, want the pipeline's own value kept", got.Commit)
	}
	if got.RepoURL != "git@example.com:org/app.git" {
		t.Errorf("RepoURL = %q, want it filled from the TaskRun", got.RepoURL)
	}
	// Nothing was pushed, so nothing may be reported as published. The build
	// task's digest is the local archive's, not a registry digest.
	if got.ImageURL != "" || got.ImageDigest != "" {
		t.Errorf("image = %q@%q, want empty for a build that never pushed", got.ImageURL, got.ImageDigest)
	}
}
