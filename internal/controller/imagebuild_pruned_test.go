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
	"testing"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
)

// Tekton Pruner deletes a PipelineRun some minutes after it finishes. A build
// whose run has gone is settled from what was recorded and never run again:
// creating the run anew would build and sign the same commit a second time.
func TestABuildWhosePipelineRunWasPrunedIsNotRunAgain(t *testing.T) {
	const runName = "your-app-main-abc1234-run"
	running := func() *supplychainv1alpha1.ImageBuild {
		ib := newImageBuild("your-app-main-abc1234", "your-app", "main", "abc1234")
		ib.Status.Phase = phaseRunning
		ib.Status.PipelineRunRef = runName
		return ib
	}
	result := func(phase string) *supplychainv1alpha1.ImageBuildResult {
		r := &supplychainv1alpha1.ImageBuildResult{
			ObjectMeta: metav1.ObjectMeta{Name: "your-app-main-abc1234", Namespace: "default"},
		}
		r.Status.Phase = phase
		return r
	}
	run := &tektonv1.PipelineRun{ObjectMeta: metav1.ObjectMeta{Name: runName, Namespace: "default"}}

	cases := []struct {
		name string
		// objects the cached client and the API server both hold
		objects []client.Object
		// objects only the API server holds (not yet in the cache)
		apiOnly       []client.Object
		build         *supplychainv1alpha1.ImageBuild
		wantPhase     string
		wantCondition string // reason of the PipelineRunDeleted condition; "" for none
	}{
		{
			name:          "pruned after it succeeded",
			objects:       []client.Object{result(phaseSucceeded)},
			build:         running(),
			wantPhase:     phaseSucceeded,
			wantCondition: "OutcomeFromResult",
		},
		{
			name:          "pruned after it failed",
			objects:       []client.Object{result(phaseFailed)},
			build:         running(),
			wantPhase:     phaseFailed,
			wantCondition: "OutcomeFromResult",
		},
		{
			name:          "pruned before anything was recorded",
			build:         running(),
			wantPhase:     phaseFailed,
			wantCondition: "NoRecordedOutcome",
		},
		{
			name:      "its run still exists",
			objects:   []client.Object{run.DeepCopy()},
			build:     running(),
			wantPhase: phaseRunning,
		},
		{
			name:      "its run was just created and is not in the cache yet",
			apiOnly:   []client.Object{run.DeepCopy()},
			build:     running(),
			wantPhase: phaseRunning,
		},
		{
			name: "a new build, before it has a run",
			build: func() *supplychainv1alpha1.ImageBuild {
				ib := newImageBuild("your-app-main-abc1234", "your-app", "main", "abc1234")
				ib.Status.Phase = phasePending
				return ib
			}(),
			wantPhase: phasePending,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := ownershipScheme(t)
			cached := fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(append([]client.Object{c.build}, c.objects...)...).
				WithStatusSubresource(&supplychainv1alpha1.ImageBuild{}).Build()
			api := fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(append(append([]client.Object{c.build.DeepCopy()}, c.objects...), c.apiOnly...)...).Build()

			r := &ImageBuildReconciler{Client: cached, Scheme: scheme, APIReader: api}
			if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(c.build)}); err != nil {
				t.Fatalf("reconcile: %v", err)
			}

			var got supplychainv1alpha1.ImageBuild
			if err := cached.Get(ctx, client.ObjectKeyFromObject(c.build), &got); err != nil {
				t.Fatal(err)
			}
			if got.Status.Phase != c.wantPhase {
				t.Errorf("phase: got %q, want %q", got.Status.Phase, c.wantPhase)
			}
			cond := meta.FindStatusCondition(got.Status.Conditions, conditionRunDeleted)
			switch {
			case c.wantCondition == "" && cond != nil:
				t.Errorf("unexpected %s condition: %s", conditionRunDeleted, cond.Reason)
			case c.wantCondition != "" && (cond == nil || cond.Reason != c.wantCondition):
				t.Errorf("%s condition: got %v, want reason %s", conditionRunDeleted, cond, c.wantCondition)
			}

			var runs tektonv1.PipelineRunList
			if err := cached.List(ctx, &runs); err != nil {
				t.Fatal(err)
			}
			want := 0
			for _, o := range c.objects {
				if _, ok := o.(*tektonv1.PipelineRun); ok {
					want++
				}
			}
			if len(runs.Items) != want {
				t.Errorf("PipelineRuns: got %d, want %d; the build must not be run again", len(runs.Items), want)
			}
		})
	}
}
