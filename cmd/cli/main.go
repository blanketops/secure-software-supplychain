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
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	installer "github.com/ntlaletsi70/secure-software-supply-chain/cmd/cli/installer"
	"github.com/ntlaletsi70/secure-software-supply-chain/cmd/cli/ui"
)

func main() {
	root := &cobra.Command{
		Use:   "supplychain",
		Short: "Secure Software Supply Chain CLI",
		Long:  "CLI for installing and managing the Secure Software Supply Chain platform dependencies.",
	}

	root.AddCommand(installCmd())
	root.AddCommand(uninstallCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(observeCmd())
	root.AddCommand(initSonarQubeCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func installCmd() *cobra.Command {
	var kubeconfig string
	var dryRun bool
	var webhookHost string
	var uiHost string
	var signingIdentity string
	var trustDomain string
	var fromStep string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install supply chain dependencies onto the cluster",
		Long: `Installs all supply chain platform dependencies in the correct order:
  1. MetalLB
  2. Tekton Pipelines, Triggers, Chains, Dashboard, Tasks, Results
  3. Sigstore (Fulcio, Rekor, Policy Controller)
  4. NGINX Ingress Controller
  5. SonarQube

All manifests are embedded in the binary — no network access required
beyond connectivity to the Kubernetes API server.

Use --webhook-host to set the public hostname for ingress routing
(e.g. your Tailscale Funnel URL). This substitutes WEBHOOK_HOST in
ingress manifests for the Tekton Dashboard and SonarQube.

Example:
  supplychain install --webhook-host pop-os.tailf8145.ts.net`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			i, err := installer.NewWithOptions(kubeconfig, dryRun, installer.Options{
				WebhookHost:     webhookHost,
				UIHost:          uiHost,
				SigningIdentity: signingIdentity,
				TrustDomain:     trustDomain,
				FromStep:        fromStep,
			})
			if err != nil {
				return fmt.Errorf("failed to create installer: %w", err)
			}
			return i.Install(ctx)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to in-cluster or ~/.kube/config)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print manifests without applying")
	cmd.Flags().StringVar(&webhookHost, "webhook-host", "", "Public hostname for ingress routing (e.g. pop-os.tailf8145.ts.net)")
	cmd.Flags().StringVar(&uiHost, "ui-host", installer.DefaultUIHost,
		"Hostname the Tekton Dashboard and SonarQube are served on; keep it different from --webhook-host so they are not published with the webhook")
	cmd.Flags().StringVar(&signingIdentity, "signing-identity", installer.IdentityKubernetes,
		"How workloads identify themselves to Fulcio: \"kubernetes\" (ServiceAccount tokens) or \"spiffe\" (installs SPIRE; signatures carry SPIFFE IDs)")
	cmd.Flags().StringVar(&trustDomain, "trust-domain", installer.DefaultTrustDomain,
		"SPIFFE trust domain, used with --signing-identity spiffe")
	cmd.Flags().StringVar(&fromStep, "from-step", "",
		"Resume an interrupted install at this step (the name shown in the progress output, e.g. \"Tekton Chains\")")
	return cmd
}

func uninstallCmd() *cobra.Command {
	var kubeconfig string

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove supply chain dependencies from the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			i, err := installer.New(kubeconfig, false)
			if err != nil {
				return fmt.Errorf("failed to create installer: %w", err)
			}
			return i.Uninstall(ctx)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig")
	return cmd
}

func statusCmd() *cobra.Command {
	var kubeconfig string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check the status of supply chain dependencies",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			i, err := installer.New(kubeconfig, false)
			if err != nil {
				return fmt.Errorf("failed to create installer: %w", err)
			}
			return i.Status(ctx)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig")
	return cmd
}

func observeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "observe [rbac]",
		Short: "Open the supply chain observer UI in your browser",
		Long: `Starts kubectl proxy and opens the embedded supply chain observer UI.

  supplychain observe        open the supply chain dashboard
  supplychain observe rbac   open the RBAC audit dashboard`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			page := "supply_chain.html"
			if len(args) > 0 && args[0] == "rbac" {
				page = "rbac.html"
			}

			fmt.Println("  Secure Software Supply Chain observer")
			fmt.Println("  ────────────────────────────────")

			return ui.Serve(ctx, page)
		},
	}

	return cmd
}

// initSonarQubeCmd bootstraps SonarQube after a fresh install.
// Connects to SonarQube, changes the default password, generates a token,
// and patches the ClusterSecretStore so pipelines can authenticate.
func initSonarQubeCmd() *cobra.Command {
	var kubeconfig string
	var newPassword string

	cmd := &cobra.Command{
		Use:   "init-sonarqube",
		Short: "Bootstrap SonarQube after install",
		Long: `Bootstraps SonarQube after a fresh install:

  1. Waits for SonarQube to be ready
  2. Changes the default admin password
  3. Generates a user token named "supply-chain"
  4. Patches the ClusterSecretStore with the token at /supplychain/sonarqube/token

Run this once after 'supplychain install' completes.

Example:
  supplychain init-sonarqube --new-password MySecurePass123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if newPassword == "" {
				return fmt.Errorf("--new-password is required")
			}
			ctx := context.Background()
			i, err := installer.New(kubeconfig, false)
			if err != nil {
				return fmt.Errorf("failed to create installer: %w", err)
			}
			return i.InitSonarQube(ctx, newPassword)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to in-cluster or ~/.kube/config)")
	cmd.Flags().StringVar(&newPassword, "new-password", "", "New admin password for SonarQube (required)")
	_ = cmd.MarkFlagRequired("new-password")
	return cmd
}
