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
package pruner

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

const (
	// DefaultRetentionWindow is how long to keep completed/failed PipelineRuns.
	// After this window, they are eligible for pruning.
	DefaultRetentionWindow = 24 * time.Hour

	// DefaultKeepSucceeded is the minimum number of succeeded PipelineRuns to
	// retain per ImageBuild regardless of age — useful for audit trails.
	DefaultKeepSucceeded = 3

	// DefaultKeepFailed is the minimum number of failed PipelineRuns to retain
	// per ImageBuild for debugging purposes.
	DefaultKeepFailed = 1
)

// Pruner deletes completed or failed PipelineRuns that exceed the retention window.
// It runs as a periodic cleanup called from the ImageBuildReconciler after a
// PipelineRun reaches a terminal state.
//
// Retention rules (applied in order):
//  1. PipelineRuns still running are never pruned.
//  2. The most recent N succeeded runs are always kept.
//  3. The most recent N failed runs are always kept.
//  4. All remaining terminal runs older than the retention window are deleted.
type Pruner struct {
	Client          client.Client
	Log             logr.Logger
	RetentionWindow time.Duration
	KeepSucceeded   int
	KeepFailed      int
}

// New creates a Pruner with default retention settings.
func New(c client.Client, log logr.Logger) *Pruner {
	return &Pruner{
		Client:          c,
		Log:             log,
		RetentionWindow: DefaultRetentionWindow,
		KeepSucceeded:   DefaultKeepSucceeded,
		KeepFailed:      DefaultKeepFailed,
	}
}

// PruneForImageBuild deletes eligible PipelineRuns owned by the given ImageBuild.
// Called after a PipelineRun reaches a terminal state (Succeeded or Failed).
func (p *Pruner) PruneForImageBuild(
	ctx context.Context,
	ib *supplyv1alpha1.ImageBuild,
) error {
	log := p.Log.WithValues(
		"imageBuild", ib.Name,
		"namespace", ib.Namespace,
	)

	// List all PipelineRuns in the namespace labelled with this ImageBuild.
	var runs tektonv1.PipelineRunList
	if err := p.Client.List(ctx, &runs,
		client.InNamespace(ib.Namespace),
		client.MatchingLabels{
			"blanketops.dev/image-build": ib.Name,
		},
	); err != nil {
		return fmt.Errorf("listing PipelineRuns for %s: %w", ib.Name, err)
	}

	if len(runs.Items) == 0 {
		return nil
	}

	succeeded, failed, running := classify(runs.Items)

	log.V(1).Info("pruner scan",
		"succeeded", len(succeeded),
		"failed", len(failed),
		"running", len(running),
	)

	deleted := 0

	// Prune succeeded runs beyond the keep threshold.
	for idx, run := range succeeded {
		if idx < p.KeepSucceeded {
			continue // keep the most recent N
		}
		if !p.eligible(run) {
			continue
		}
		if err := p.Client.Delete(ctx, &run); err != nil {
			log.Error(err, "failed to delete PipelineRun", "name", run.Name)
			continue
		}
		log.Info("pruned succeeded PipelineRun",
			"name", run.Name,
			"completedAt", completedAt(run),
		)
		deleted++
	}

	// Prune failed runs beyond the keep threshold.
	for idx, run := range failed {
		if idx < p.KeepFailed {
			continue
		}
		if !p.eligible(run) {
			continue
		}
		if err := p.Client.Delete(ctx, &run); err != nil {
			log.Error(err, "failed to delete PipelineRun", "name", run.Name)
			continue
		}
		log.Info("pruned failed PipelineRun",
			"name", run.Name,
			"completedAt", completedAt(run),
		)
		deleted++
	}

	if deleted > 0 {
		log.Info("pruning complete", "deleted", deleted)
	}

	return nil
}

// PruneNamespace prunes all eligible PipelineRuns in a namespace regardless
// of ImageBuild ownership. Used for global cleanup on a schedule.
func (p *Pruner) PruneNamespace(ctx context.Context, namespace string) error {
	log := p.Log.WithValues("namespace", namespace)

	var runs tektonv1.PipelineRunList
	if err := p.Client.List(ctx, &runs, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("listing PipelineRuns in %s: %w", namespace, err)
	}

	deleted := 0
	for _, run := range runs.Items {
		run := run
		if isRunning(run) {
			continue
		}
		if !p.eligible(run) {
			continue
		}
		if err := p.Client.Delete(ctx, &run); err != nil {
			log.Error(err, "failed to delete PipelineRun", "name", run.Name)
			continue
		}
		log.Info("pruned PipelineRun", "name", run.Name)
		deleted++
	}

	if deleted > 0 {
		log.Info("namespace pruning complete", "deleted", deleted)
	}

	return nil
}

// eligible returns true if a PipelineRun has exceeded the retention window.
func (p *Pruner) eligible(run tektonv1.PipelineRun) bool {
	t := completedAt(run)
	if t.IsZero() {
		return false
	}
	return time.Since(t) > p.RetentionWindow
}

// classify splits PipelineRuns into succeeded, failed, and running buckets.
// Results are sorted newest-first within each bucket.
func classify(runs []tektonv1.PipelineRun) (succeeded, failed, running []tektonv1.PipelineRun) {
	for _, run := range runs {
		run := run
		switch {
		case isRunning(run):
			running = append(running, run)
		case isSucceeded(run):
			succeeded = append(succeeded, run)
		default:
			failed = append(failed, run)
		}
	}

	// Sort newest-first so keep-N logic retains the most recent.
	sortNewestFirst(succeeded)
	sortNewestFirst(failed)

	return succeeded, failed, running
}

func isRunning(run tektonv1.PipelineRun) bool {
	return run.Status.CompletionTime == nil
}

func isSucceeded(run tektonv1.PipelineRun) bool {
	for _, cond := range run.Status.Conditions {
		if cond.Type == "Succeeded" && cond.Status == "True" {
			return true
		}
	}
	return false
}

func completedAt(run tektonv1.PipelineRun) time.Time {
	if run.Status.CompletionTime == nil {
		return time.Time{}
	}
	return run.Status.CompletionTime.Time
}

func sortNewestFirst(runs []tektonv1.PipelineRun) {
	for i := 0; i < len(runs); i++ {
		for j := i + 1; j < len(runs); j++ {
			if completedAt(runs[j]).After(completedAt(runs[i])) {
				runs[i], runs[j] = runs[j], runs[i]
			}
		}
	}
}
