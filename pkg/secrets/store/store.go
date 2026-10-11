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

import "strings"

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

// The store's keys. Each is one secret in Vault holding a single value, in
// the field named by Field. A build asks the store for exactly these, so a
// store of any other kind has to serve the same keys.
const (
	// The SSH identity builds clone the source with.
	GitPrivateKey = Prefix + "/git/ssh-privatekey"
	GitKnownHosts = Prefix + "/git/known-hosts"
	GitSSHConfig  = Prefix + "/git/ssh-config"
	// A Docker config.json with push access to the registry.
	RegistryConfig = Prefix + "/registry/config"
	// A token that can manage the repository's webhooks.
	GitHubToken = Prefix + "/github/token"
	// Written by `supplychain init-sonarqube`.
	SonarQubeToken = Prefix + "/sonarqube/token"

	// Field is the field of each secret that holds its value.
	Field = "value"
)

// Keys are the store's keys in the order they are listed, each with what it
// is for.
var Keys = []struct{ Key, Purpose string }{
	{GitPrivateKey, "SSH key that can read the repository"},
	{GitKnownHosts, "the git host's keys (ssh-keyscan github.com)"},
	{GitSSHConfig, "SSH client configuration for the git host"},
	{RegistryConfig, "Docker config.json with push access"},
	{GitHubToken, "token that can manage the repository's webhooks"},
	{SonarQubeToken, "written by `supplychain init-sonarqube`"},
}

// RefreshInterval is how often External Secrets reads each secret again. A
// credential rotated in Vault reaches the builds within this time, with
// nothing to delete or recreate.
const RefreshInterval = "1m"

// Key completes a key given without the prefix every key shares, which is how
// the CLI takes them: "git/ssh-privatekey" is supplychain/git/ssh-privatekey.
// A key that already has the prefix is returned as it is.
func Key(name string) string {
	name = strings.Trim(name, "/")
	if name == Prefix || strings.HasPrefix(name, Prefix+"/") {
		return name
	}
	return Prefix + "/" + name
}

// Ref is the secretStoreRef of an ExternalSecret.
func Ref() map[string]any {
	return map[string]any{"name": Name, "kind": Kind}
}

// RemoteRef is the remoteRef of one key: the secret, and the field its value
// is in.
func RemoteRef(key string) map[string]any {
	return map[string]any{"key": key, "property": Field}
}
