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
	"reflect"
	"strings"
	"testing"
)

// The case this exists for: a cluster installed with SPIFFE identities and
// its keys in Vault, and the installer run again with a flag forgotten. It
// keeps what the cluster has. Before, it fell back to the default, and
// Fulcio's CA and Rekor's key were replaced.
func TestSettleSettingsKeepsWhatTheClusterHas(t *testing.T) {
	installed := map[string]string{
		settingIdentity: IdentitySPIFFE, settingTrustDomain: "your-domain.example",
		settingResidency: ResidencyVault, settingWebhookHost: "your-machine.your-tailnet.ts.net",
	}
	given := Options{SigningIdentity: IdentitySPIFFE}.givenSettings() // --key-residency left out
	settled, kept, err := settleSettings(given, installed, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(settled, installed) {
		t.Errorf("settled on %v, want what the cluster has: %v", settled, installed)
	}
	if want := []string{settingResidency, settingTrustDomain, settingWebhookHost}; !reflect.DeepEqual(kept, want) {
		t.Errorf("kept %v, want %v", kept, want)
	}

	// Nothing given at all keeps everything.
	if settled, _, err := settleSettings(Options{}.givenSettings(), installed, false); err != nil ||
		settled[settingResidency] != ResidencyVault || settled[settingIdentity] != IdentitySPIFFE {
		t.Errorf("with no flags: %v, %v", settled, err)
	}
}

// Changing what a cluster trusts is refused unless it is asked for, and the
// refusal says what would be replaced.
func TestSettleSettingsRefusesAnUnaskedTrustChange(t *testing.T) {
	installed := map[string]string{
		settingIdentity: IdentitySPIFFE, settingTrustDomain: "your-domain.example", settingResidency: ResidencyVault,
	}
	for name, change := range map[string]Options{
		settingResidency:   {KeyResidency: ResidencyCluster},
		settingIdentity:    {SigningIdentity: IdentityKubernetes},
		settingTrustDomain: {TrustDomain: "another.example"},
	} {
		_, _, err := settleSettings(change.givenSettings(), installed, false)
		if err == nil || !strings.Contains(err.Error(), "--"+name) || !strings.Contains(err.Error(), "--allow-trust-change") ||
			!strings.Contains(err.Error(), whatChanging[name]) {
			t.Errorf("changing %s: %v", name, err)
		}
		settled, _, err := settleSettings(change.givenSettings(), installed, true)
		if err != nil || settled[name] != change.givenSettings()[name] {
			t.Errorf("changing %s on purpose: %v, %v", name, settled[name], err)
		}
	}

	// Saying what the cluster already has is not a change.
	same := Options{SigningIdentity: IdentitySPIFFE, KeyResidency: ResidencyVault}
	if _, _, err := settleSettings(same.givenSettings(), installed, false); err != nil {
		t.Errorf("repeating the cluster's own settings was refused: %v", err)
	}
	// The webhook host is not a trust setting, and may change.
	moved := Options{WebhookHost: "another-machine.your-tailnet.ts.net"}
	installed[settingWebhookHost] = "your-machine.your-tailnet.ts.net"
	if settled, _, err := settleSettings(moved.givenSettings(), installed, false); err != nil ||
		settled[settingWebhookHost] != moved.WebhookHost {
		t.Errorf("changing the webhook host: %v, %v", settled[settingWebhookHost], err)
	}
}

// A new cluster has nothing to keep: what is given is used, and what is not
// is left for the defaults.
func TestSettleSettingsOnANewCluster(t *testing.T) {
	settled, kept, err := settleSettings(
		Options{SigningIdentity: IdentitySPIFFE, KeyResidency: ResidencyVault}.givenSettings(), map[string]string{}, false)
	if err != nil || len(kept) != 0 || settled[settingResidency] != ResidencyVault || settled[settingTrustDomain] != "" {
		t.Errorf("settled %v, kept %v, %v", settled, kept, err)
	}
	options := Options{SigningIdentity: settled[settingIdentity], TrustDomain: settled[settingTrustDomain]}
	if err := options.defaultAndValidate(); err != nil || options.TrustDomain != DefaultTrustDomain {
		t.Errorf("defaults after settling: %+v, %v", options, err)
	}
}

// A cluster installed before the settings were recorded is read from what
// runs on it: how Fulcio is started says where its key is.
func TestResidencyOfARunningFulcio(t *testing.T) {
	fulcio := find(t, manifestObjects(t, "dependencies/sigstore/fulcio/release.yaml"), kindDeployment, "fulcio-server")
	if got := residencyOf(fulcio); got != ResidencyCluster {
		t.Errorf("Fulcio as the manifest has it reads as %q, want %q", got, ResidencyCluster)
	}
	keysInVaultMutation(fulcio)
	if got := residencyOf(fulcio); got != ResidencyVault {
		t.Errorf("Fulcio with its key in Vault reads as %q, want %q", got, ResidencyVault)
	}
}
