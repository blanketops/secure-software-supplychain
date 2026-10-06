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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
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

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
)

const (
	resultsTLSSecretName = "tekton-results-tls"
	resultsTLSNamespace  = "tekton-pipelines"

	// webhookHostPlaceholder is replaced in ingress manifests at apply time
	// with the actual public hostname (e.g. Tailscale Funnel URL).
	webhookHostPlaceholder = "WEBHOOK_HOST"

	// uiHostPlaceholder is replaced in the ingress routes of the hosted UIs
	// (Tekton Dashboard, SonarQube). They get a hostname of their own so that
	// publishing the webhook host does not publish them with it.
	uiHostPlaceholder = "UI_HOST"

	// DefaultUIHost resolves to the local machine in browsers and most
	// resolvers, and is never routable from outside it.
	DefaultUIHost = "supplychain.localhost"

	// sigstore trust anchor configmap — mounted by signTask and any verifier.
	sigstoreRootsName = "blanketops-sigstore-roots"

	// readyTimeout bounds each wait for a dependency to come up. It is mostly
	// image pulls, which on a slow connection take far longer than the workload
	// needs to start. A wait that gives up too early forces a re-run, and a
	// re-run re-creates the sigstore setup Jobs, which regenerate keys the
	// running services have already loaded.
	readyTimeout = time.Hour

	// signerOIDCIssuer issues the ServiceAccount tokens exchanged with Fulcio.
	signerOIDCIssuer = "https://kubernetes.default.svc.cluster.local"

	// chainsIdentityTokenFile is where the Chains Deployment mounts its
	// projected ServiceAccount token (see dependencies/tekton/chains/release.yaml).
	chainsIdentityTokenFile = "/var/run/sigstore/cosign/oidc-token"

	// ctlog secret coords.
	ctfePublicKeySecret = "ctlog-public-key"
	ctfePublicKeyNS     = "ctlog-system"
)

// sigstoreRootsNamespaces lists every namespace that needs the trust anchor
// configmap mounted by pipeline tasks and Chains.
var sigstoreRootsNamespaces = []string{"default", "tekton-chains"}

// ---------------------------------------------------------------------------
// step / installOrder
// ---------------------------------------------------------------------------

// step represents a named installation phase with a set of manifest paths.
type step struct {
	Name     string
	Paths    []string
	PreHook  func(ctx context.Context, i *Installer) error
	PostHook func(ctx context.Context, i *Installer) error
	// Skip leaves the step out of this install, for example SPIRE when the
	// signing identity is not SPIFFE.
	Skip func(i *Installer) bool
	// RegistersCRDs makes the installer re-read the API after the step, so the
	// kinds it defined can be applied by the steps that follow.
	RegistersCRDs bool
}

// onlyForSPIFFE skips a step unless the signing identity is SPIFFE.
func onlyForSPIFFE(i *Installer) bool { return !i.spiffe() }

// installOrder defines the sequence in which dependencies are applied.
var installOrder = []step{
	{
		Name:  "MetalLB Install",
		Paths: []string{"dependencies/metallb/release"},
	},
	{
		Name:  "Tekton Pipelines",
		Paths: []string{"dependencies/tekton/pipelines"},
	},
	{
		Name:  "Tekton Triggers",
		Paths: []string{"dependencies/tekton/triggers/core"},
	},
	{
		Name:  "Tekton Interceptors",
		Paths: []string{"dependencies/tekton/triggers/interceptors"},
	},
	{
		Name:          "SPIRE CRDs",
		Paths:         []string{"dependencies/spire/crds"},
		Skip:          onlyForSPIFFE,
		RegistersCRDs: true,
	},
	{
		// SPIRE issues the SPIFFE identities workloads sign with. It comes
		// before Fulcio, which has to be able to reach its OIDC discovery.
		Name:  "SPIRE",
		Paths: []string{"dependencies/spire/release"},
		Skip:  onlyForSPIFFE,
		PostHook: func(ctx context.Context, i *Installer) error {
			waitSp := newSpinner("Waiting for the SPIRE server to be ready...")
			waitSp.start()
			if err := i.waitForStatefulSet(ctx, spireNamespace, "spire-server", readyTimeout); err != nil {
				waitSp.fail("SPIRE server not ready")
				return err
			}
			waitSp.succeed("SPIRE server ready")
			return nil
		},
	},
	{
		// Which pods get which SPIFFE ID. Applied once the server, which
		// validates and reconciles them, is up.
		Name:  "SPIRE Identities",
		Paths: []string{"dependencies/spire/identities"},
		Skip:  onlyForSPIFFE,
		PostHook: func(ctx context.Context, i *Installer) error {
			waitSp := newSpinner("Waiting for SPIRE OIDC discovery to be ready...")
			waitSp.start()
			if err := i.waitForDeployment(ctx, spireNamespace, "spire-spiffe-oidc-discovery-provider", readyTimeout); err != nil {
				waitSp.fail("SPIRE OIDC discovery not ready")
				return err
			}
			waitSp.succeed("SPIRE OIDC discovery ready")
			return i.removeDefaultSPIFFEID(ctx)
		},
	},
	{
		Name:  "Fulcio",
		Paths: []string{"dependencies/sigstore/fulcio"},
		PostHook: func(ctx context.Context, i *Installer) error {
			if !i.spiffe() {
				return nil
			}
			cfgSp := newSpinner("Configuring Fulcio to accept SPIFFE identities...")
			cfgSp.start()
			if err := i.configureFulcioIssuers(ctx); err != nil {
				cfgSp.fail("Failed to configure Fulcio issuers")
				return err
			}
			cfgSp.succeed("Fulcio accepts identities from " + i.opts.TrustDomain)
			return nil
		},
	},
	{
		Name:  "Rekor",
		Paths: []string{"dependencies/sigstore/rekor"},
		// Rekor's pod mounts its signing key, so the key has to be there first.
		PreHook: func(ctx context.Context, i *Installer) error {
			return i.ensureRekorSigningKey(ctx)
		},
		PostHook: func(ctx context.Context, i *Installer) error {
			// Trillian's database is created by a Job that only retries a few
			// times; on a slow connection MySQL is not up before it gives up.
			dbSp := newSpinner("Waiting for the Trillian database...")
			dbSp.start()
			if err := i.waitForDeployment(ctx, "trillian-system", "trillian-mysql", readyTimeout); err != nil {
				dbSp.fail("Trillian MySQL not ready")
				return err
			}
			if err := i.ensureJobSucceeded(ctx, "dependencies/sigstore/rekor",
				"trillian-system", "rekor-trillian-createdb", readyTimeout); err != nil {
				dbSp.fail("Trillian database was not created")
				return err
			}
			dbSp.succeed("Trillian database ready")
			return nil
		},
	},
	{
		Name:  "Tekton Chains",
		Paths: []string{"dependencies/tekton/chains"},
		PostHook: func(ctx context.Context, i *Installer) error {
			// 1. Wait for Chains controller before touching its config.
			waitSp := newSpinner("Waiting for Tekton Chains to be ready...")
			waitSp.start()
			if err := i.waitForDeployment(ctx, "tekton-chains", "tekton-chains-controller", readyTimeout); err != nil {
				waitSp.fail("Tekton Chains not ready")
				return err
			}
			waitSp.succeed("Tekton Chains ready")

			// 2. Overwrite the default chains-config with our BlanketOps config.
			cfgSp := newSpinner("Applying BlanketOps chains-config...")
			cfgSp.start()
			if err := i.applyChainsConfig(ctx); err != nil {
				cfgSp.fail("Failed to apply chains-config")
				return err
			}
			cfgSp.succeed("chains-config applied")

			// With SPIFFE, Chains signs as its SPIFFE identity: give it the
			// Workload API socket, and record the trust domain where the
			// operator reads it.
			if i.spiffe() {
				idSp := newSpinner("Giving Tekton Chains its SPIFFE identity...")
				idSp.start()
				if err := i.giveChainsSPIFFEIdentity(ctx); err != nil {
					idSp.fail("Failed to mount the SPIFFE socket into Tekton Chains")
					return err
				}
				if err := i.applyTektonSpireConfig(ctx); err != nil {
					idSp.fail("Failed to record the trust domain")
					return err
				}
				idSp.succeed("Tekton Chains signs as spiffe://" + i.opts.TrustDomain + "/ns/tekton-chains/sa/tekton-chains-controller")
			}

			// 3. Collect the three in-cluster sigstore trust anchors and
			//    create blanketops-sigstore-roots in all required namespaces.
			//    This must run after Fulcio, Rekor, and ctlog are up, which
			//    they are — they were installed before Chains in this order.
			rootsSp := newSpinner("Fetching sigstore trust anchors...")
			rootsSp.start()
			if err := i.ensureSigstoreRoots(ctx); err != nil {
				rootsSp.fail("Failed to fetch sigstore trust anchors")
				return err
			}
			rootsSp.succeed("blanketops-sigstore-roots created")
			return nil
		},
	},
	{
		// Admission side of signing: serves the ClusterImagePolicy and
		// TrustRoot CRDs that SupplyChainPolicy renders. It only enforces in
		// namespaces labelled policy.sigstore.dev/include=true.
		Name:  "Policy Controller",
		Paths: []string{"dependencies/sigstore/policy-controller"},
		PostHook: func(ctx context.Context, i *Installer) error {
			waitSp := newSpinner("Waiting for Policy Controller to be ready...")
			waitSp.start()
			if err := i.waitForDeployment(ctx, "cosign-system", "policy-controller-webhook", readyTimeout); err != nil {
				waitSp.fail("Policy Controller not ready")
				return err
			}
			waitSp.succeed("Policy Controller ready")
			return nil
		},
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
		Name:  "Tekton Results",
		Paths: []string{"dependencies/tekton/results"},
		PreHook: func(ctx context.Context, i *Installer) error {
			return i.ensureResultsTLS(ctx)
		},
	},
	{
		Name:  "MetalLB Dependencies",
		Paths: []string{"dependencies/metallb/setup"},
	},
	{
		// Apply the nginx controller manifest first, then wait for it to be
		// ready before applying ingress routes — the admission webhook must
		// be up before any Ingress objects are created.
		Name:  "NGINX Ingress Controller",
		Paths: []string{"dependencies/ingress/controller"},
		PostHook: func(ctx context.Context, i *Installer) error {
			waitSp := newSpinner("Waiting for NGINX Ingress Controller to be ready...")
			waitSp.start()
			if err := i.waitForDeployment(ctx, "ingress-nginx", "ingress-nginx-controller", readyTimeout); err != nil {
				waitSp.fail("NGINX Ingress Controller not ready")
				return err
			}
			waitSp.succeed("NGINX Ingress Controller ready")
			// A re-applied manifest drops the webhook's CA; put it back.
			return i.ensureIngressWebhookCA(ctx)
		},
	},
	{
		// Ingress routes are applied after the controller is ready.
		// UI_HOST is substituted with the --ui-host flag value.
		Name:  "Ingress Routes",
		Paths: []string{"dependencies/ingress/routes"},
	},
	{
		Name:  "SonarQube",
		Paths: []string{"dependencies/sonarqube"},
		// Both SonarQube and its database read the password when they start.
		PreHook: func(ctx context.Context, i *Installer) error {
			return i.ensureSonarQubeDatabasePassword(ctx)
		},
		PostHook: func(ctx context.Context, i *Installer) error {
			waitSp := newSpinner("Waiting for the SonarQube database to be ready...")
			waitSp.start()
			if err := i.waitForStatefulSet(ctx, sonarNamespace, sonarDatabaseSTS, readyTimeout); err != nil {
				waitSp.fail("SonarQube database not ready")
				return err
			}
			waitSp.succeed("SonarQube database ready")
			return nil
		},
	},
}

// ---------------------------------------------------------------------------
// statusChecks
// ---------------------------------------------------------------------------

var statusChecks = []struct {
	Namespace  string
	Deployment string
	Label      string
}{
	{Namespace: "tekton-pipelines", Deployment: "tekton-pipelines-controller", Label: "Tekton Pipelines"},
	{Namespace: "tekton-pipelines", Deployment: "tekton-pipelines-webhook", Label: "Tekton Webhook"},
	{Namespace: "tekton-pipelines", Deployment: "tekton-triggers-controller", Label: "Tekton Triggers"},
	{Namespace: "tekton-pipelines", Deployment: "tekton-triggers-webhook", Label: "Tekton Triggers Webhook"},
	{Namespace: "tekton-pipelines", Deployment: "tekton-triggers-core-interceptors", Label: "Tekton Interceptors"},
	{Namespace: "fulcio-system", Deployment: "fulcio-server", Label: "Fulcio"},
	{Namespace: "rekor-system", Deployment: "rekor-server", Label: "Rekor"},
	{Namespace: "tekton-chains", Deployment: "tekton-chains-controller", Label: "Tekton Chains"},
	{Namespace: "cosign-system", Deployment: "policy-controller-webhook", Label: "Policy Controller"},
	{Namespace: "tekton-pipelines", Deployment: "tekton-dashboard", Label: "Tekton Dashboard"},
	{Namespace: "tekton-pipelines", Deployment: "tekton-results-api", Label: "Tekton Results API"},
	{Namespace: "tekton-pipelines", Deployment: "tekton-results-watcher", Label: "Tekton Results Watcher"},
	{Namespace: "ingress-nginx", Deployment: "ingress-nginx-controller", Label: "NGINX Ingress"},
}

// ---------------------------------------------------------------------------
// Installer
// ---------------------------------------------------------------------------

// Installer applies embedded supply chain manifests to a Kubernetes cluster.
type Installer struct {
	dynamic     dynamic.Interface
	discovery   discovery.DiscoveryInterface
	mapper      meta.RESTMapper
	dryRun      bool
	webhookHost string
	uiHost      string
	opts        Options
	// restConfig is kept for operations that need a raw REST client
	// (e.g. reading pod logs), where the dynamic client is insufficient.
	restConfig *rest.Config
}

// New creates an Installer from a kubeconfig path.
func New(kubeconfig string, dryRun bool) (*Installer, error) {
	return NewWithOptions(kubeconfig, dryRun, Options{})
}

// NewWithOptions creates an Installer. Empty options take their defaults: the
// UIs on DefaultUIHost, and the Kubernetes signing identity.
func NewWithOptions(kubeconfig string, dryRun bool, opts Options) (*Installer, error) {
	if err := opts.defaultAndValidate(); err != nil {
		return nil, err
	}
	webhookHost, uiHost := opts.WebhookHost, opts.UIHost
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
		dynamic:     dynClient,
		discovery:   disc,
		mapper:      mapper,
		dryRun:      dryRun,
		webhookHost: webhookHost,
		uiHost:      uiHost,
		opts:        opts,
		restConfig:  config,
	}, nil
}

// ---------------------------------------------------------------------------
// Install / Uninstall / Status
// ---------------------------------------------------------------------------

// Install applies all supply chain dependencies in order.
func (i *Installer) Install(ctx context.Context) error {
	fmt.Println()
	fmt.Println("🔧 Installing Secure Software Supply Chain dependencies...")
	if i.webhookHost != "" {
		fmt.Printf("   Webhook host: %s\n", i.webhookHost)
	} else {
		fmt.Println("   ⚠  No --webhook-host set — ingress routes will use WEBHOOK_HOST placeholder.")
		fmt.Println("      Run with --webhook-host <host> to configure ingress routing.")
	}
	fmt.Printf("   UI host:      %s (Tekton Dashboard, SonarQube)\n", i.uiHost)
	if i.spiffe() {
		fmt.Printf("   Identity:     SPIFFE, trust domain %s\n", i.opts.TrustDomain)
	} else {
		fmt.Println("   Identity:     Kubernetes ServiceAccount tokens")
	}
	fmt.Println()

	steps, err := i.stepsToRun()
	if err != nil {
		return err
	}
	if i.opts.FromStep != "" {
		fmt.Printf("   Resuming from: %s\n\n", steps[0].Name)
	}

	for idx, s := range steps {
		fmt.Printf("[%d/%d] %s\n", idx+1, len(steps), s.Name)

		if s.PreHook != nil && !i.dryRun {
			if err := s.PreHook(ctx, i); err != nil {
				return fmt.Errorf("  ✗ %s pre-hook failed: %w", s.Name, err)
			}
		}

		sp := newSpinner(fmt.Sprintf("Applying %s...", s.Name))
		if !i.dryRun {
			sp.start()
		}

		var applyErr error
		for _, dir := range s.Paths {
			if err := i.applyDirectory(ctx, dir); err != nil {
				applyErr = fmt.Errorf("%s failed: %w", s.Name, err)
				break
			}
		}
		if applyErr != nil {
			if !i.dryRun {
				sp.fail(applyErr.Error())
			}
			return applyErr
		}

		if !i.dryRun {
			sp.succeed(fmt.Sprintf("%s applied", s.Name))
		} else {
			fmt.Printf("  ✓ %s applied (dry-run)\n", s.Name)
		}

		if s.PostHook != nil && !i.dryRun {
			if err := s.PostHook(ctx, i); err != nil {
				return fmt.Errorf("  ✗ %s post-hook failed: %w", s.Name, err)
			}
		}

		if s.RegistersCRDs && !i.dryRun {
			waitSp := newSpinner(fmt.Sprintf("Waiting for the %s to register...", s.Name))
			waitSp.start()
			time.Sleep(10 * time.Second)
			if err := i.refreshMapper(); err != nil {
				waitSp.fail("failed to refresh API discovery")
				return fmt.Errorf("failed to refresh API discovery: %w", err)
			}
			waitSp.succeed(s.Name + " registered")
		}

		if s.Name == "Tekton Pipelines" && !i.dryRun {
			waitSp := newSpinner("Waiting for Tekton CRDs to register...")
			waitSp.start()
			time.Sleep(10 * time.Second)
			if err := i.refreshMapper(); err != nil {
				waitSp.fail("failed to refresh API discovery")
				return fmt.Errorf("failed to refresh API discovery: %w", err)
			}
			waitSp.succeed("Tekton CRDs registered")
		}

		if s.Name == "Tekton Triggers" && !i.dryRun {
			waitSp := newSpinner("Waiting for Tekton Triggers CRDs to register...")
			waitSp.start()
			time.Sleep(10 * time.Second)
			if err := i.refreshMapper(); err != nil {
				waitSp.fail("failed to refresh API discovery")
				return fmt.Errorf("failed to refresh API discovery: %w", err)
			}
			waitSp.succeed("Tekton Triggers CRDs registered")
		}
	}

	fmt.Println()
	fmt.Println("✅ All supply chain dependencies installed.")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Wait for pods to be ready:  kubectl get pods -n tekton-pipelines")
	fmt.Println("  2. Bootstrap SonarQube:        supplychain init-sonarqube --new-password <password>")
	fmt.Println("  3. Deploy the supply chain operator")
	fmt.Println("  4. Apply a SupplyChain CR")
	fmt.Println()
	return nil
}

// stepsToRun is the install order for this run: the steps that apply to the
// chosen signing identity, starting at Options.FromStep when one is given.
func (i *Installer) stepsToRun() ([]step, error) {
	var steps []step
	for _, s := range installOrder {
		if s.Skip == nil || !s.Skip(i) {
			steps = append(steps, s)
		}
	}
	if i.opts.FromStep == "" {
		return steps, nil
	}
	names := make([]string, 0, len(steps))
	for idx, s := range steps {
		if strings.EqualFold(s.Name, i.opts.FromStep) {
			return steps[idx:], nil
		}
		names = append(names, s.Name)
	}
	return nil, fmt.Errorf("no step %q; the steps are: %s", i.opts.FromStep, strings.Join(names, ", "))
}

// setupResult is where a one-time setup Job leaves what it made: a Secret, or
// one key of a ConfigMap.
type setupResult struct {
	Secret    string
	ConfigMap string
	Key       string
}

// setupJobs are the Jobs that must run exactly once in the life of a cluster,
// and the result that shows each one has.
//
// They generate what cannot be generated twice: the keys Fulcio and the CT log
// sign with, and the Merkle trees behind Rekor and the CT log. Finished Jobs
// are removed by their TTL, so on a later run the Job is simply missing. Run
// again, the key Jobs replace keys that everything already trusts, and the
// tree Jobs start a new, empty log: every signature made before then is "not
// found in the transparency log", and every image carrying one is refused at
// admission.
var setupJobs = map[string]setupResult{
	"fulcio-system/fulcio-createcerts":         {Secret: "fulcio-server-secret"},
	"ctlog-system/fulcio-ctlog-createctconfig": {Secret: "ctlog-secret"},
	"ctlog-system/ctlog-createtree":            {ConfigMap: "ctlog-config", Key: "treeID"},
	"rekor-system/rekor-createtree":            {ConfigMap: "rekor-config", Key: "treeID"},
}

// setupResults are the ConfigMaps a setup Job writes its result into, and the
// key it writes. The manifests ship them holding a placeholder only; applying
// that over one a Job has filled in would erase the tree the log lives in.
var setupResults = map[string]string{
	"ctlog-system/ctlog-config": "treeID",
	"rekor-system/rekor-config": "treeID",
}

// setupJobAlreadyRan reports whether obj is a one-time setup Job whose result
// already exists.
func (i *Installer) setupJobAlreadyRan(ctx context.Context, obj *unstructured.Unstructured) (bool, error) {
	if obj.GetKind() != "Job" {
		return false, nil
	}
	result, isSetupJob := setupJobs[obj.GetNamespace()+"/"+obj.GetName()]
	if !isSetupJob {
		return false, nil
	}
	name, gvr := result.Secret, schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	if result.ConfigMap != "" {
		name, gvr = result.ConfigMap, configMapGVR
	}
	found, err := i.dynamic.Resource(gvr).Namespace(obj.GetNamespace()).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking for %s/%s: %w", obj.GetNamespace(), name, err)
	}
	if result.Key == "" {
		return true, nil
	}
	return holdsSetupResult(found, result.Key), nil
}

// holdsSetupResult reports whether a ConfigMap already carries the value a
// setup Job writes under key.
func holdsSetupResult(cm *unstructured.Unstructured, key string) bool {
	value, _, _ := unstructured.NestedString(cm.Object, "data", key)
	return value != ""
}

// Uninstall removes all supply chain dependencies in reverse order.
func (i *Installer) Uninstall(ctx context.Context) error {
	fmt.Println("🗑  Removing Secure Software Supply Chain dependencies...")
	fmt.Println()
	for idx := len(installOrder) - 1; idx >= 0; idx-- {
		s := installOrder[idx]
		fmt.Printf("[%d/%d] Removing %s\n", len(installOrder)-idx, len(installOrder), s.Name)
		for _, dir := range s.Paths {
			if err := i.deleteDirectory(ctx, dir); err != nil {
				fmt.Printf("  ⚠ %s: %v\n", s.Name, err)
				continue
			}
		}
		if s.Name == "Tekton Results" {
			_ = i.deleteResultsTLS(ctx)
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
				fmt.Printf("  ✗ %-30s  not installed\n", check.Label)
			} else {
				fmt.Printf("  ✗ %-30s  error: %v\n", check.Label, err)
			}
			continue
		}
		replicas, _, _ := unstructured.NestedInt64(deploy.Object, "status", "availableReplicas")
		desired, _, _ := unstructured.NestedInt64(deploy.Object, "spec", "replicas")
		if replicas >= desired && desired > 0 {
			fmt.Printf("  ✓ %-30s  running (%d/%d)\n", check.Label, replicas, desired)
		} else {
			fmt.Printf("  ⏳ %-30s  starting (%d/%d)\n", check.Label, replicas, desired)
		}
	}
	fmt.Println()
	return nil
}

// ---------------------------------------------------------------------------
// Readiness helpers
// ---------------------------------------------------------------------------

// waitForDeployment polls until the named deployment has all replicas available
// or the timeout is exceeded.
func (i *Installer) waitForDeployment(ctx context.Context, namespace, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		deploy, err := i.dynamic.Resource(
			schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			replicas, _, _ := unstructured.NestedInt64(deploy.Object, "status", "availableReplicas")
			desired, _, _ := unstructured.NestedInt64(deploy.Object, "spec", "replicas")
			if replicas >= desired && desired > 0 {
				return nil
			}
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("deployment %s/%s not ready after %s", namespace, name, timeout)
}

// ---------------------------------------------------------------------------
// Sigstore trust anchors
// ---------------------------------------------------------------------------

// ensureSigstoreRoots collects the three in-cluster sigstore trust anchors
// and creates the blanketops-sigstore-roots ConfigMap in all required namespaces.
//
// Sources:
//   - fulcio-root.pem: fulcio-pub-key secret in fulcio-system (key: "cert")
//   - ctfe.pub:        ctlog-public-key secret in ctlog-system (key: "public")
//   - rekor.pub:       fetched via a short-lived Job (Rekor exposes no secret)
//
// ensureSigstoreRoots collects the three in-cluster sigstore trust anchors
// and creates the blanketops-sigstore-roots ConfigMap in all required namespaces.
func (i *Installer) ensureSigstoreRoots(ctx context.Context) error {
	// Wait for Rekor to be ready — it's installed before Chains but may
	// still be starting when this PostHook fires.
	rekorSp := newSpinner("Waiting for Rekor to be ready...")
	rekorSp.start()
	if err := i.waitForDeployment(ctx, "rekor-system", "rekor-server", readyTimeout); err != nil {
		rekorSp.fail("Rekor not ready")
		return err
	}
	rekorSp.succeed("Rekor ready")

	// Wait for Fulcio to be ready too.
	fulcioSp := newSpinner("Waiting for Fulcio to be ready...")
	fulcioSp.start()
	if err := i.waitForDeployment(ctx, "fulcio-system", "fulcio-server", readyTimeout); err != nil {
		fulcioSp.fail("Fulcio not ready")
		return err
	}
	fulcioSp.succeed("Fulcio ready")

	// The CT log's keys and config are written by a setup Job that needs Fulcio
	// and only retries a few times; make sure it ran to completion.
	if err := i.ensureJobSucceeded(ctx, "dependencies/sigstore/fulcio",
		"ctlog-system", "fulcio-ctlog-createctconfig", readyTimeout); err != nil {
		return fmt.Errorf("CT log config was not created: %w", err)
	}

	// ctlog-public-key is created by a post-install Job after ctlog starts.
	ctlogSp := newSpinner("Waiting for ctlog-public-key secret...")
	ctlogSp.start()
	if err := i.waitForSecret(ctx, ctfePublicKeyNS, ctfePublicKeySecret, readyTimeout); err != nil {
		ctlogSp.fail("ctlog-public-key secret not found")
		return err
	}
	ctlogSp.succeed("ctlog-public-key secret ready")

	// Also wait for fulcio-pub-key — created by a Job after Fulcio starts.
	fulcioPubSp := newSpinner("Waiting for fulcio-pub-key secret...")
	fulcioPubSp.start()
	if err := i.waitForSecret(ctx, "fulcio-system", "fulcio-pub-key", readyTimeout); err != nil {
		fulcioPubSp.fail("fulcio-pub-key secret not found")
		return err
	}
	fulcioPubSp.succeed("fulcio-pub-key secret ready")

	fulcioRoot, err := i.readSecretKey(ctx, "fulcio-system", "fulcio-pub-key", "cert")
	// ... rest unchanged
	if err != nil {
		return fmt.Errorf("failed to read Fulcio root cert: %w", err)
	}

	ctfePub, err := i.readSecretKey(ctx, ctfePublicKeyNS, ctfePublicKeySecret, "public")
	if err != nil {
		return fmt.Errorf("failed to read CTFE public key: %w", err)
	}

	rekorPub, err := i.fetchRekorPublicKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch Rekor public key: %w", err)
	}

	cmData := map[string]any{
		"fulcio-root.pem": string(fulcioRoot),
		"ctfe.pub":        string(ctfePub),
		"rekor.pub":       string(rekorPub),
	}

	cmGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	for _, ns := range sigstoreRootsNamespaces {
		cm := &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata": map[string]any{
					"name":      sigstoreRootsName,
					"namespace": ns,
					"labels": map[string]any{
						"blanketops.dev/managed": "true",
					},
				},
				"data": cmData,
			},
		}
		existing, err := i.dynamic.Resource(cmGVR).Namespace(ns).Get(ctx, sigstoreRootsName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, err := i.dynamic.Resource(cmGVR).Namespace(ns).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("failed to create %s in %s: %w", sigstoreRootsName, ns, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check %s in %s: %w", sigstoreRootsName, ns, err)
		} else {
			cm.SetResourceVersion(existing.GetResourceVersion())
			if _, err := i.dynamic.Resource(cmGVR).Namespace(ns).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to update %s in %s: %w", sigstoreRootsName, ns, err)
			}
		}
	}
	return nil
}

// readSecretKey reads and base64-decodes a single key from a Kubernetes secret.
// Kubernetes stores secret data as base64 in the API response.
func (i *Installer) readSecretKey(ctx context.Context, namespace, secretName, key string) ([]byte, error) {
	secretGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	secret, err := i.dynamic.Resource(secretGVR).Namespace(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, secretName, err)
	}
	data, _, _ := unstructured.NestedStringMap(secret.Object, "data")
	encoded, ok := data[key]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing key %q", namespace, secretName, key)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s/%s[%s]: %w", namespace, secretName, key, err)
	}
	return decoded, nil
}

// fetchRekorPublicKey spawns a short-lived Job that curls the Rekor public key
// endpoint from inside the cluster, reads stdout via the pod log API, then
// cleans up. Rekor exposes no Kubernetes secret for its signing key.
func (i *Installer) fetchRekorPublicKey(ctx context.Context) ([]byte, error) {
	const (
		jobName = "blanketops-fetch-rekor-pub"
		jobNS   = "default"
	)
	jobGVR := schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	propagation := metav1.DeletePropagationBackground
	_ = i.dynamic.Resource(jobGVR).Namespace(jobNS).Delete(ctx, jobName, metav1.DeleteOptions{
		PropagationPolicy: &propagation,
	})
	time.Sleep(2 * time.Second)

	job := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "batch/v1",
			"kind":       "Job",
			"metadata": map[string]any{
				"name":      jobName,
				"namespace": jobNS,
				"labels":    map[string]any{"blanketops.dev/managed": "true"},
			},
			"spec": map[string]any{
				"ttlSecondsAfterFinished": int64(30),
				"template": map[string]any{
					"spec": map[string]any{
						"restartPolicy": "Never",
						"containers": []any{
							map[string]any{
								"name":  "fetch",
								"image": "curlimages/curl:latest",
								"command": []any{
									"curl", "-sf",
									"http://rekor-server.rekor-system.svc.cluster.local/api/v1/log/publicKey",
								},
							},
						},
					},
				},
			},
		},
	}

	if _, err := i.dynamic.Resource(jobGVR).Namespace(jobNS).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("failed to create rekor fetch job: %w", err)
	}

	// Poll until pod reaches terminal phase.
	deadline := time.Now().Add(2 * time.Minute)
	var logPodName string
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		pods, err := i.dynamic.Resource(podGVR).Namespace(jobNS).List(ctx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("job-name=%s", jobName),
		})
		if err != nil || len(pods.Items) == 0 {
			continue
		}
		pod := pods.Items[0]
		phase, _, _ := unstructured.NestedString(pod.Object, "status", "phase")
		if phase == "Succeeded" || phase == "Failed" {
			logPodName = pod.GetName()
			break
		}
	}
	if logPodName == "" {
		return nil, fmt.Errorf("rekor fetch job timed out waiting for pod")
	}

	// Use the raw REST request directly — avoids the NegotiatedSerializer
	// requirement of RESTClientFor by using the config's transport directly.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/log", i.restConfig.Host, jobNS, logPodName),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build log request: %w", err)
	}
	transport, err := rest.TransportFor(i.restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build transport: %w", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pod logs: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read pod log response: %w", err)
	}

	_ = i.dynamic.Resource(jobGVR).Namespace(jobNS).Delete(ctx, jobName, metav1.DeleteOptions{
		PropagationPolicy: &propagation,
	})

	pub := bytes.TrimSpace(raw)
	if len(pub) == 0 {
		return nil, fmt.Errorf("rekor public key fetch returned empty response")
	}
	return pub, nil
}

// ---------------------------------------------------------------------------
// Chains config
// ---------------------------------------------------------------------------

// chainsConfig is the Tekton Chains configuration for this stack: keyless
// signing against the in-cluster Fulcio and Rekor, with SLSA v1.0 provenance
// stored next to the image it describes.
func chainsConfig(opts Options) map[string]any {
	const (
		// slsa/v2alpha4 is Chains' name for SLSA v1.0 provenance. "in-toto" and
		// "slsa/v1" are both the older v0.2 predicate.
		provenanceFormat = "slsa/v2alpha4"
		fulcioURL        = "http://fulcio-server.fulcio-system.svc.cluster.local"
		rekorURL         = "http://rekor-server.rekor-system.svc.cluster.local"
	)
	config := map[string]any{
		"artifacts.taskrun.format":                     provenanceFormat,
		"artifacts.taskrun.storage":                    "oci",
		"artifacts.taskrun.signer":                     "x509",
		"artifacts.oci.storage":                        "oci",
		"artifacts.oci.format":                         "simplesigning",
		"artifacts.oci.signer":                         "x509",
		"artifacts.pipelinerun.format":                 provenanceFormat,
		"artifacts.pipelinerun.storage":                "oci",
		"artifacts.pipelinerun.signer":                 "x509",
		"artifacts.pipelinerun.enable-deep-inspection": "true",
		// storage.oci.repository is left unset on purpose: signatures and
		// attestations are then stored alongside the image, which is where
		// cosign and policy-controller look for them.
		"builder.id":                  "https://tekton.dev/chains/v2",
		"builddefinition.buildtype":   "https://tekton.dev/chains/v2/slsa",
		"signers.x509.fulcio.enabled": "true",
		"signers.x509.fulcio.address": fulcioURL,
		"signers.x509.rekor.address":  rekorURL,
		"transparency.enabled":        "true",
		"transparency.url":            rekorURL,
	}
	if opts.SigningIdentity == IdentitySPIFFE {
		// Chains asks the SPIFFE Workload API for a JWT-SVID and presents it
		// to Fulcio, which verifies it against SPIRE's OIDC discovery.
		config["signers.x509.fulcio.provider"] = "spiffe"
		config["signers.x509.fulcio.issuer"] = spireOIDCIssuer
	} else {
		// The Chains controller is given a projected ServiceAccount token for
		// the "sigstore" audience at this path; that token is its identity.
		config["signers.x509.fulcio.issuer"] = signerOIDCIssuer
		config["signers.x509.identity.token.file"] = chainsIdentityTokenFile
	}
	return config
}

// applyChainsConfig overwrites the default chains-config ConfigMap with the
// BlanketOps configuration: in-cluster Fulcio/Rekor, OCI storage, x509/keyless.
func (i *Installer) applyChainsConfig(ctx context.Context) error {
	cmGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	cm := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      "chains-config",
				"namespace": "tekton-chains",
				"labels": map[string]any{
					"app.kubernetes.io/instance": "default",
					"app.kubernetes.io/part-of":  "tekton-chains",
				},
			},
			"data": chainsConfig(i.opts),
		},
	}
	existing, err := i.dynamic.Resource(cmGVR).Namespace("tekton-chains").Get(ctx, "chains-config", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = i.dynamic.Resource(cmGVR).Namespace("tekton-chains").Create(ctx, cm, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	cm.SetResourceVersion(existing.GetResourceVersion())
	_, err = i.dynamic.Resource(cmGVR).Namespace("tekton-chains").Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// ---------------------------------------------------------------------------
// Tekton Results TLS
// ---------------------------------------------------------------------------

func (i *Installer) ensureResultsTLS(ctx context.Context) error {
	secretGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	_, err := i.dynamic.Resource(secretGVR).
		Namespace(resultsTLSNamespace).
		Get(ctx, resultsTLSSecretName, metav1.GetOptions{})
	if err == nil {
		fmt.Println("  ✓ TLS secret already exists — skipping generation")
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to check for existing TLS secret: %w", err)
	}
	fmt.Println("  🔐 Generating self-signed TLS certificate for Results API...")
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate TLS cert: %w", err)
	}
	if err := i.ensureNamespace(ctx, resultsTLSNamespace); err != nil {
		return err
	}
	secret := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]any{
				"name":      resultsTLSSecretName,
				"namespace": resultsTLSNamespace,
			},
			"type": "kubernetes.io/tls",
			"data": map[string]any{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			},
		},
	}
	_, err = i.dynamic.Resource(secretGVR).
		Namespace(resultsTLSNamespace).
		Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create TLS secret: %w", err)
	}
	fmt.Println("  ✓ TLS secret created")
	return nil
}

func (i *Installer) deleteResultsTLS(ctx context.Context) error {
	secretGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	err := i.dynamic.Resource(secretGVR).
		Namespace(resultsTLSNamespace).
		Delete(ctx, resultsTLSSecretName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func (i *Installer) ensureNamespace(ctx context.Context, name string) error {
	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	_, err := i.dynamic.Resource(nsGVR).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	ns := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata": map[string]any{
				"name": name,
			},
		},
	}
	_, err = i.dynamic.Resource(nsGVR).Create(ctx, ns, metav1.CreateOptions{})
	return err
}

func generateSelfSignedCert() (certPEM []byte, keyPEM []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("tekton-results-api-service.%s.svc.cluster.local", resultsTLSNamespace),
		},
		DNSNames: []string{
			fmt.Sprintf("tekton-results-api-service.%s.svc.cluster.local", resultsTLSNamespace),
			fmt.Sprintf("tekton-results-api-service.%s.svc", resultsTLSNamespace),
			"tekton-results-api-service",
			"localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	certBuf := &bytes.Buffer{}
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode cert PEM: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode key PEM: %w", err)
	}
	return certBuf.Bytes(), keyBuf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Core manifest application logic
// ---------------------------------------------------------------------------

// substituteManifest replaces known placeholders in manifest data.
// WEBHOOK_HOST is replaced with the configured webhook host.
func (i *Installer) substituteManifest(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte(uiHostPlaceholder), []byte(i.uiHost))
	data = bytes.ReplaceAll(data, []byte(trustDomainPlaceholder), []byte(i.opts.TrustDomain))
	if i.webhookHost == "" {
		return data
	}
	return bytes.ReplaceAll(data, []byte(webhookHostPlaceholder), []byte(i.webhookHost))
}

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
		data = i.substituteManifest(data)
		if err := i.applyManifest(ctx, data, path); err != nil {
			return fmt.Errorf("failed to apply %q: %w", path, err)
		}
	}
	return nil
}

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
		if done, err := i.setupJobAlreadyRan(ctx, obj); err != nil || done {
			return err
		}
		_, err = dr.Create(ctx, obj, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	// A ConfigMap a setup Job has written its result into is left alone.
	if key, ok := setupResults[obj.GetNamespace()+"/"+obj.GetName()]; ok && obj.GetKind() == "ConfigMap" &&
		holdsSetupResult(existing, key) {
		return nil
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	_, err = dr.Update(ctx, obj, metav1.UpdateOptions{})
	// Some objects cannot be changed once created: a Job's pod template, a
	// bound PersistentVolumeClaim's spec. The API server rejects the update as
	// invalid. The object is already there from an earlier run, so a re-run of
	// the installer keeps it rather than failing.
	if apierrors.IsInvalid(err) {
		return nil
	}
	return err
}

func (i *Installer) deleteObject(ctx context.Context, obj *unstructured.Unstructured) error {
	gvk := obj.GroupVersionKind()
	mapping, err := i.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil
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

func (i *Installer) refreshMapper() error {
	groupResources, err := restmapper.GetAPIGroupResources(i.discovery)
	if err != nil {
		return err
	}
	i.mapper = restmapper.NewDiscoveryRESTMapper(groupResources)
	return nil
}

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

// waitForSecret polls until the named secret exists or the timeout is exceeded.
func (i *Installer) waitForSecret(ctx context.Context, namespace, name string, timeout time.Duration) error {
	secretGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := i.dynamic.Resource(secretGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("secret %s/%s not found after %s", namespace, name, timeout)
}
