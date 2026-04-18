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

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"

	manifests "github.com/ntlaletsi70/blanketops-environments-supply-chain"
)

// step represents a named installation phase with a set of manifest paths.
type step struct {
	Name  string
	Paths []string
}

// installOrder defines the sequence in which dependencies are applied.
// Order matters: Tekton Pipelines CRDs must exist before Chains or Tasks.
var installOrder = []step{
	{
		Name:  "Tekton Pipelines",
		Paths: []string{"dependencies/tekton/pipelines"},
	},
	{
		Name:  "Tekton Chains",
		Paths: []string{"dependencies/tekton/chains"},
	},
	{
		Name:  "Tekton Dashboard",
		Paths: []string{"dependencies/tekton/dashboard"},
	},
	{
		Name:  "Tekton Tasks",
		Paths: []string{"dependencies/tekton/task"},
	},
	{
		Name:  "Grafeas",
		Paths: []string{"dependencies/grafeas"},
	},
}

// statusChecks are the namespaces and deployments to verify after install.
var statusChecks = []struct {
	Namespace  string
	Deployment string
	Label      string
}{
	{Namespace: "tekton-pipelines", Deployment: "tekton-pipelines-controller", Label: "Tekton Pipelines"},
	{Namespace: "tekton-chains", Deployment: "tekton-chains-controller", Label: "Tekton Chains"},
}

// Installer applies embedded supply chain manifests to a Kubernetes cluster.
type Installer struct {
	dynamic   dynamic.Interface
	discovery discovery.DiscoveryInterface
	mapper    meta.RESTMapper
	dryRun    bool
}

// New creates an Installer from a kubeconfig path.
// If kubeconfig is empty, it tries in-cluster config, then falls back to
// the default kubeconfig location.
func New(kubeconfig string, dryRun bool) (*Installer, error) {
	config, err := buildConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	disc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery client: %w", err)
	}

	groupResources, err := restmapper.GetAPIGroupResources(disc)
	if err != nil {
		return nil, fmt.Errorf("failed to get API group resources: %w", err)
	}

	mapper := restmapper.NewDiscoveryRESTMapper(groupResources)

	return &Installer{
		dynamic:   dynClient,
		discovery: disc,
		mapper:    mapper,
		dryRun:    dryRun,
	}, nil
}

// Install applies all supply chain dependencies in order.
func (i *Installer) Install(ctx context.Context) error {
	fmt.Println("🔧 Installing BlanketOps Supply Chain dependencies...")
	fmt.Println()

	for idx, s := range installOrder {
		fmt.Printf("[%d/%d] %s\n", idx+1, len(installOrder), s.Name)

		for _, dir := range s.Paths {
			if err := i.applyDirectory(ctx, dir); err != nil {
				return fmt.Errorf("  ✗ %s failed: %w", s.Name, err)
			}
		}

		// Wait briefly between major components to let CRDs register.
		if s.Name == "Tekton Pipelines" && !i.dryRun {
			fmt.Println("  ⏳ Waiting for Tekton CRDs to register...")
			time.Sleep(10 * time.Second)

			// Refresh the REST mapper after Pipelines CRDs are installed
			// so that subsequent steps (Chains, Tasks) can resolve Tekton types.
			if err := i.refreshMapper(); err != nil {
				return fmt.Errorf("  ✗ failed to refresh API discovery: %w", err)
			}
		}

		fmt.Printf("  ✓ %s applied\n", s.Name)
	}

	fmt.Println()
	fmt.Println("✅ All supply chain dependencies installed.")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Wait for pods to be ready:  kubectl get pods -n tekton-pipelines")
	fmt.Println("  2. Deploy the supply chain operator")
	fmt.Println("  3. Apply a SupplyChain CR")
	fmt.Println()

	return nil
}

// Uninstall removes all supply chain dependencies in reverse order.
func (i *Installer) Uninstall(ctx context.Context) error {
	fmt.Println("🗑  Removing BlanketOps Supply Chain dependencies...")
	fmt.Println()

	// Reverse order — remove tasks/grafeas first, then pipelines last.
	for idx := len(installOrder) - 1; idx >= 0; idx-- {
		s := installOrder[idx]
		fmt.Printf("[%d/%d] Removing %s\n", len(installOrder)-idx, len(installOrder), s.Name)

		for _, dir := range s.Paths {
			if err := i.deleteDirectory(ctx, dir); err != nil {
				// Don't fail on delete errors — resources may already be gone.
				fmt.Printf("  ⚠ %s: %v\n", s.Name, err)
				continue
			}
		}

		fmt.Printf("  ✓ %s removed\n", s.Name)
	}

	fmt.Println()
	fmt.Println("✅ Supply chain dependencies removed.")

	return nil
}

// Status checks whether key supply chain components are running.
func (i *Installer) Status(ctx context.Context) error {
	fmt.Println("📋 Supply Chain Dependency Status")
	fmt.Println()

	for _, check := range statusChecks {
		deploy, err := i.dynamic.Resource(
			schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		).Namespace(check.Namespace).Get(ctx, check.Deployment, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				fmt.Printf("  ✗ %-20s  not installed\n", check.Label)
			} else {
				fmt.Printf("  ✗ %-20s  error: %v\n", check.Label, err)
			}
			continue
		}

		replicas, _, _ := unstructured.NestedInt64(deploy.Object, "status", "availableReplicas")
		desired, _, _ := unstructured.NestedInt64(deploy.Object, "spec", "replicas")

		if replicas >= desired && desired > 0 {
			fmt.Printf("  ✓ %-20s  running (%d/%d)\n", check.Label, replicas, desired)
		} else {
			fmt.Printf("  ⏳ %-20s  starting (%d/%d)\n", check.Label, replicas, desired)
		}
	}

	fmt.Println()

	return nil
}

// applyDirectory reads all YAML files from an embedded directory and applies
// each document to the cluster.
func (i *Installer) applyDirectory(ctx context.Context, dir string) error {
	entries, err := manifests.Dependencies.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read embedded directory %q: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := manifests.Dependencies.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", path, err)
		}

		if err := i.applyManifest(ctx, data, path); err != nil {
			return fmt.Errorf("failed to apply %q: %w", path, err)
		}
	}

	return nil
}

// deleteDirectory reads all YAML files from an embedded directory and deletes
// each document from the cluster.
func (i *Installer) deleteDirectory(ctx context.Context, dir string) error {
	entries, err := manifests.Dependencies.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read embedded directory %q: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := manifests.Dependencies.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", path, err)
		}

		if err := i.deleteManifest(ctx, data); err != nil {
			return err
		}
	}

	return nil
}

// applyManifest parses a multi-document YAML and applies each resource
// using server-side apply semantics (create or update).
func (i *Installer) applyManifest(ctx context.Context, data []byte, source string) error {
	reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))

	docIndex := 0
	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read YAML document %d: %w", docIndex, err)
		}

		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		obj := &unstructured.Unstructured{}
		if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc)).Decode(obj); err != nil {
			// Skip non-resource documents (e.g. comments-only).
			continue
		}

		if obj.GetKind() == "" {
			continue
		}

		if i.dryRun {
			fmt.Printf("  → [dry-run] %s/%s (%s)\n", obj.GetKind(), obj.GetName(), obj.GetNamespace())
			docIndex++
			continue
		}

		if err := i.applyObject(ctx, obj); err != nil {
			return fmt.Errorf("failed to apply %s/%s: %w", obj.GetKind(), obj.GetName(), err)
		}

		docIndex++
	}

	return nil
}

// deleteManifest parses a multi-document YAML and deletes each resource.
func (i *Installer) deleteManifest(ctx context.Context, data []byte) error {
	reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))

	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		obj := &unstructured.Unstructured{}
		if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc)).Decode(obj); err != nil {
			continue
		}

		if obj.GetKind() == "" {
			continue
		}

		_ = i.deleteObject(ctx, obj)
	}

	return nil
}

// applyObject creates or updates a single unstructured object on the cluster.
func (i *Installer) applyObject(ctx context.Context, obj *unstructured.Unstructured) error {
	gvk := obj.GroupVersionKind()
	mapping, err := i.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return fmt.Errorf("no mapping for %s: %w", gvk, err)
	}

	var dr dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		ns := obj.GetNamespace()
		if ns == "" {
			ns = "default"
		}
		dr = i.dynamic.Resource(mapping.Resource).Namespace(ns)
	} else {
		dr = i.dynamic.Resource(mapping.Resource)
	}

	existing, err := dr.Get(ctx, obj.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = dr.Create(ctx, obj, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}

	// Preserve the resourceVersion for update.
	obj.SetResourceVersion(existing.GetResourceVersion())
	_, err = dr.Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

// deleteObject removes a single unstructured object from the cluster.
func (i *Installer) deleteObject(ctx context.Context, obj *unstructured.Unstructured) error {
	gvk := obj.GroupVersionKind()
	mapping, err := i.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil // Can't map — probably already gone.
	}

	var dr dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		ns := obj.GetNamespace()
		if ns == "" {
			ns = "default"
		}
		dr = i.dynamic.Resource(mapping.Resource).Namespace(ns)
	} else {
		dr = i.dynamic.Resource(mapping.Resource)
	}

	return dr.Delete(ctx, obj.GetName(), metav1.DeleteOptions{})
}

// refreshMapper rebuilds the REST mapper after new CRDs have been registered.
func (i *Installer) refreshMapper() error {
	groupResources, err := restmapper.GetAPIGroupResources(i.discovery)
	if err != nil {
		return err
	}
	i.mapper = restmapper.NewDiscoveryRESTMapper(groupResources)
	return nil
}

// buildConfig resolves a kubeconfig in priority order:
// 1. Explicit path
// 2. In-cluster config
// 3. Default kubeconfig (~/.kube/config)
func buildConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not determine home directory: %w", err)
	}

	return clientcmd.BuildConfigFromFlags("", filepath.Join(home, ".kube", "config"))
}
