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
package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
)

var jobGVR = schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}

// ensureJobSucceeded waits for a setup Job to succeed, re-creating it from the
// embedded manifests if it has given up.
//
// The upstream setup Jobs start as soon as they are applied and retry a fixed
// number of times. When the service they need is still pulling its image, they
// use up their attempts before it is reachable and are never run again, which
// leaves everything behind them waiting forever.
func (i *Installer) ensureJobSucceeded(ctx context.Context, dir, namespace, name string, timeout time.Duration) error {
	jobs := i.dynamic.Resource(jobGVR).Namespace(namespace)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		job, err := jobs.Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			// The step that calls this has just applied the Job, so a missing
			// one has finished and been removed by its TTL. It must not be
			// created again: several of these Jobs generate keys, and a second
			// run would replace keys the running services have already loaded.
			return nil
		case err != nil:
			return err
		case jobSucceeded(job):
			return nil
		case jobGaveUp(job):
			propagation := metav1.DeletePropagationForeground
			if err := jobs.Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &propagation}); err != nil &&
				!apierrors.IsNotFound(err) {
				return err
			}
			if err := i.waitForJobGone(ctx, namespace, name); err != nil {
				return err
			}
			if err := i.createJobFromManifests(ctx, dir, namespace, name); err != nil {
				return err
			}
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("job %s/%s did not succeed within %s", namespace, name, timeout)
}

func jobSucceeded(job *unstructured.Unstructured) bool {
	succeeded, _, _ := unstructured.NestedInt64(job.Object, "status", "succeeded")
	return succeeded > 0
}

// jobGaveUp reports whether a Job has stopped retrying.
func jobGaveUp(job *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(job.Object, "status", "conditions")
	for _, c := range conditions {
		condition, ok := c.(map[string]any)
		if ok && condition["type"] == "Failed" && condition["status"] == "True" {
			return true
		}
	}
	return false
}

func (i *Installer) waitForJobGone(ctx context.Context, namespace, name string) error {
	for range 60 {
		_, err := i.dynamic.Resource(jobGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("job %s/%s was not deleted", namespace, name)
}

func (i *Installer) createJobFromManifests(ctx context.Context, dir, namespace, name string) error {
	job, err := findEmbeddedJob(dir, namespace, name)
	if err != nil {
		return err
	}
	_, err = i.dynamic.Resource(jobGVR).Namespace(namespace).Create(ctx, job, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// findEmbeddedJob returns the named Job from the manifests embedded under dir.
func findEmbeddedJob(dir, namespace, name string) (*unstructured.Unstructured, error) {
	entries, err := manifests.Dependencies.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded directory %q: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		data, err := manifests.Dependencies.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
		for {
			doc, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			obj := &unstructured.Unstructured{}
			if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc)).Decode(obj); err != nil {
				continue
			}
			if obj.GetKind() == "Job" && obj.GetName() == name && obj.GetNamespace() == namespace {
				return obj, nil
			}
		}
	}
	return nil, fmt.Errorf("job %s/%s not found in %s", namespace, name, dir)
}
