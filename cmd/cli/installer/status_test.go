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
	"io/fs"
	"strings"
	"testing"

	manifests "github.com/blanketops/secure-software-supplychain"
)

// The status report names workloads by hand. Every one of them has to be
// something the installer applies, under that kind, namespace and name, or
// the report would call a working install broken. And every workload the
// installer applies has to be in the report, or it would call a broken one
// working.
func TestStatusCoversWhatTheInstallerRuns(t *testing.T) {
	installed := map[string]bool{}
	err := fs.WalkDir(manifests.Dependencies, "dependencies", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		for _, obj := range manifestObjects(t, path) {
			if _, isWorkload := workloadGVRs[obj.GetKind()]; !isWorkload {
				continue
			}
			namespace := obj.GetNamespace()
			if namespace == "" {
				namespace = sonarNamespace
			}
			installed[obj.GetKind()+" "+namespace+"/"+obj.GetName()] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	reported := map[string]bool{}
	for _, group := range statusGroups {
		for _, w := range group.Workloads {
			key := w.Kind + " " + w.Namespace + "/" + w.Name
			reported[key] = true
			if !installed[key] {
				t.Errorf("status reports %s (%s), which no manifest installs", key, w.Label)
			}
		}
	}
	// Reported elsewhere in the report, or not something a build depends on.
	exempt := map[string]string{
		"Deployment vault/supply-chain-svid": "its work shows as the secret store logging in",
		"DaemonSet metallb-system/speaker":   "announces the ingress address; MetalLB's controller is reported",
	}
	for key := range installed {
		if !reported[key] && exempt[key] == "" {
			t.Errorf("the installer runs %s, which status does not report", key)
		}
	}
}
