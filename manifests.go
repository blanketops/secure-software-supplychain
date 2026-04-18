/*
Copyright 2026.
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

import "embed"

// Dependencies embeds all YAML manifests under the dependencies/ directory.
// This file must live at the repo root (or be referenced with the correct
// relative path) so that go:embed can resolve the directory.
//
// The embed directive is relative to the package directory, so this package
// should be placed at the repo root or the embed path adjusted accordingly.
//
//go:embed dependencies/tekton/pipelines/*.yaml dependencies/tekton/chains/*.yaml dependencies/tekton/dashboard/*.yaml dependencies/tekton/results/*.yaml dependencies/tekton/task/*.yaml dependencies/sigstore/fulcio/*.yaml dependencies/sigstore/rekor/*.yaml dependencies/grafeas/*.yaml
var Dependencies embed.FS
