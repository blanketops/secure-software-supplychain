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

package evidence

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"time"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
)

// PipelineRunEntry is the run of a RunLogEntry for the PipelineRun itself.
const PipelineRunEntry = "PipelineRun"

const (
	labelPipelineRun  = "tekton.dev/pipelineRun"
	labelPipelineTask = "tekton.dev/pipelineTask"
)

// RunLogEntries returns the transparency log entries Tekton Chains made when
// it signed run and each of its TaskRuns, in log order, read from their
// chains.tekton.dev/transparency annotations and completed from the log. A
// run Chains did not sign has none. An entry the log cannot be asked about is
// kept with its index, and the error says so: nothing is dropped silently.
func RunLogEntries(ctx context.Context, c client.Reader, run *tektonv1.PipelineRun, log *rekor) ([]supplyv1alpha1.RunLogEntry, error) {
	type annotated struct {
		run        string
		annotation string
	}
	runs := []annotated{{PipelineRunEntry, run.Annotations[ChainsTransparencyAnnotation]}}
	var taskRuns tektonv1.TaskRunList
	if err := c.List(ctx, &taskRuns, client.InNamespace(run.Namespace),
		client.MatchingLabels{labelPipelineRun: run.Name}); err != nil {
		return nil, fmt.Errorf("listing the TaskRuns of %s: %w", run.Name, err)
	}
	for _, tr := range taskRuns.Items {
		runs = append(runs, annotated{tr.Labels[labelPipelineTask], tr.Annotations[ChainsTransparencyAnnotation]})
	}

	var entries []supplyv1alpha1.RunLogEntry
	var problems []error
	for _, r := range runs {
		if r.annotation == "" {
			continue
		}
		index, err := logIndexOf(r.annotation)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", r.run, err))
			continue
		}
		entry := supplyv1alpha1.RunLogEntry{Run: r.run, RekorLogIndex: index}
		uuid, found, err := log.byIndex(ctx, index)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: transparency log entry %d: %w", r.run, index, err))
		} else {
			entry.RekorUUID, entry.RekorLogID = uuid, found.LogID
			if found.IntegratedTime > 0 {
				at := metav1.NewTime(time.Unix(found.IntegratedTime, 0).UTC())
				entry.IntegratedAt = &at
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].RekorLogIndex < entries[j].RekorLogIndex })
	return entries, errors.Join(problems...)
}

// logIndexOf reads the log index out of the entry URL Chains annotates a run
// with, .../api/v1/log/entries?logIndex=N.
func logIndexOf(entryURL string) (int64, error) {
	u, err := url.Parse(entryURL)
	if err != nil {
		return 0, fmt.Errorf("transparency annotation %q: %w", entryURL, err)
	}
	index, err := strconv.ParseInt(u.Query().Get("logIndex"), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("transparency annotation %q has no log index", entryURL)
	}
	return index, nil
}
