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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func signedRun(name, task string, logIndex string) client.Object {
	meta := metav1.ObjectMeta{Name: name, Namespace: "ns", Labels: map[string]string{
		"tekton.dev/pipelineRun": "run-1",
	}}
	if logIndex != "" {
		meta.Annotations = map[string]string{
			ChainsSignedAnnotation:       "true",
			ChainsTransparencyAnnotation: "https://rekor.example/api/v1/log/entries?logIndex=" + logIndex,
		}
	}
	if task == "" {
		return &tektonv1.PipelineRun{ObjectMeta: meta}
	}
	meta.Labels["tekton.dev/pipelineTask"] = task
	return &tektonv1.TaskRun{ObjectMeta: meta}
}

// TestRunLogEntries: every run Tekton Chains signed, the TaskRuns and the
// PipelineRun, has its transparency log entry recorded, completed from the
// log; a TaskRun Chains did not sign has none.
func TestRunLogEntries(t *testing.T) {
	log := newFakeRekor()
	for _, index := range []int64{41, 45, 53} {
		log.add("sha256:unused", index, map[string]any{"kind": "intoto"})
	}
	server := httptest.NewServer(log)
	defer server.Close()

	scheme := runtime.NewScheme()
	if err := tektonv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	run := signedRun("run-1", "", "53").(*tektonv1.PipelineRun)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		run,
		signedRun("run-1-trivy", "vulnerability-scan-trivy", "45"),
		signedRun("run-1-clone", "git-clone", "41"),
		signedRun("run-1-unsigned", "verify-image-policy", ""),
		// Another run's TaskRun is not this build's.
		&tektonv1.TaskRun{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "ns", Labels: map[string]string{
			"tekton.dev/pipelineRun": "run-2", "tekton.dev/pipelineTask": "git-clone",
		}, Annotations: map[string]string{ChainsTransparencyAnnotation: "https://rekor.example/api/v1/log/entries?logIndex=99"}}},
	).Build()

	got, err := RunLogEntries(context.Background(), c, run, &rekor{base: server.URL, http: server.Client()})
	if err != nil {
		t.Fatalf("RunLogEntries: %v", err)
	}
	want := []struct {
		run   string
		index int64
	}{{"git-clone", 41}, {"vulnerability-scan-trivy", 45}, {PipelineRunEntry, 53}}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %+v; want %d", len(got), got, len(want))
	}
	for i, w := range want {
		e := got[i]
		if e.Run != w.run || e.RekorLogIndex != w.index {
			t.Errorf("entry %d = %s %d; want %s %d", i, e.Run, e.RekorLogIndex, w.run, w.index)
		}
		if e.RekorUUID == "" || e.RekorLogID != testLogID || e.IntegratedAt == nil ||
			!e.IntegratedAt.Equal(&metav1.Time{Time: time.Unix(1791236744+w.index, 0)}) {
			t.Errorf("entry %d not completed from the log: %+v", i, e)
		}
	}
}

// TestRunLogEntriesReportsWhatTheLogDoesNotHave: an annotated index the log
// does not know is kept, with the error, so nothing is silently dropped.
func TestRunLogEntriesReportsWhatTheLogDoesNotHave(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	scheme := runtime.NewScheme()
	_ = tektonv1.AddToScheme(scheme)
	run := signedRun("run-1", "", "53").(*tektonv1.PipelineRun)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(run).Build()

	got, err := RunLogEntries(context.Background(), c, run, &rekor{base: server.URL, http: server.Client()})
	if err == nil || !strings.Contains(err.Error(), "53") {
		t.Fatalf("error = %v; want one naming log index 53", err)
	}
	if len(got) != 1 || got[0].RekorLogIndex != 53 || got[0].RekorUUID != "" {
		t.Fatalf("entries = %+v; want index 53 kept without what the log would add", got)
	}
}
