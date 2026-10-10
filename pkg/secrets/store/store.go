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

// Package store says where the supply chain's credentials are kept.
//
// They live in HashiCorp Vault, in its key-value engine, and reach a build as
// ordinary Secrets through External Secrets Operator: every ExternalSecret the
// operator creates reads from one ClusterSecretStore, which logs in to Vault
// with a Kubernetes ServiceAccount. The operator itself never talks to Vault
// and holds no Vault credential.
package store

const (
	// Name and Kind identify the ClusterSecretStore, which the installer
	// creates and points at Vault.
	Name = "secure-software-supply-chain-store"
	Kind = "ClusterSecretStore"

	// Mount is the key-value (version 2) engine in Vault, and Prefix the
	// folder under it that everything here lives in. The Vault policy the
	// store logs in with can read below Prefix and nothing else.
	Mount  = "secret"
	Prefix = "supplychain"
)

// The secrets, one per kind of credential, and the fields each one holds.
const (
	// Git is the SSH identity builds clone the source with.
	Git              = Prefix + "/git"
	GitPrivateKey    = "ssh-privatekey"
	GitPublicKey     = "ssh-publickey"
	GitKnownHosts    = "known-hosts"
	GitSSHConfig     = "ssh-config"
	Registry         = Prefix + "/registry"
	RegistryConfig   = "config" // a Docker config.json with push access
	GitHub           = Prefix + "/github"
	GitHubToken      = "token" // manages the repository's webhooks
	SonarQube        = Prefix + "/sonarqube"
	SonarQubeToken   = "token" // written by `supplychain init-sonarqube`
	groupPrefixSlash = Prefix + "/"
)

// RefreshInterval is how often External Secrets reads each secret again. A
// credential rotated in Vault reaches the builds within this time, with
// nothing to delete or recreate.
const RefreshInterval = "1m"

// Groups are the secrets by the short name the CLI takes ("git"), with the
// fields a working install needs in each.
var Groups = map[string][]string{
	"git":       {GitPrivateKey, GitKnownHosts, GitSSHConfig},
	"registry":  {RegistryConfig},
	"github":    {GitHubToken},
	"sonarqube": {SonarQubeToken},
}

// Path is the Vault path of a group, as an ExternalSecret names it.
func Path(group string) string { return groupPrefixSlash + group }

// Ref is the secretStoreRef of an ExternalSecret.
func Ref() map[string]any {
	return map[string]any{"name": Name, "kind": Kind}
}

// RemoteRef is the remoteRef of one field of one secret.
func RemoteRef(path, field string) map[string]any {
	return map[string]any{"key": path, "property": field}
}
