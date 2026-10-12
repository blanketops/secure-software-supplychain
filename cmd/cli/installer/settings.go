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
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A cluster is installed with a few choices that cannot be changed by
// accident without consequences: how workloads identify themselves, in which
// trust domain, and where the signing keys are kept. Each decides a trust
// anchor. Running the installer again with one of them left out used to fall
// back to its default, which replaced Fulcio's CA and Rekor's key under a
// cluster that had been using others, and everything signed before stopped
// verifying.
//
// So the installer remembers. What a cluster was installed with is kept in a
// ConfigMap; a flag that is left out takes the value from there, and a flag
// that contradicts it is refused unless the change is asked for by name.

const (
	settingsNamespace = "kube-system"
	settingsConfigMap = "secure-software-supply-chain-install"

	settingIdentity    = "signing-identity"
	settingTrustDomain = "trust-domain"
	settingResidency   = "key-residency"
	settingWebhookHost = "webhook-host"
)

// trustSettings are the settings that decide a trust anchor, in the order
// they are reported.
var trustSettings = []string{settingIdentity, settingTrustDomain, settingResidency}

// whatChanging says what each of them replaces, for the refusal.
var whatChanging = map[string]string{
	settingIdentity:    "the issuer in every signing certificate, which the admission policies match",
	settingTrustDomain: "the identity in every signing certificate, which the admission policies match",
	settingResidency:   "Fulcio's CA key and the key Rekor signs the log with",
}

// givenSettings is what was said on the command line; a setting that was not
// given is empty.
func (o Options) givenSettings() map[string]string {
	return map[string]string{
		settingIdentity:    o.SigningIdentity,
		settingTrustDomain: o.TrustDomain,
		settingResidency:   o.KeyResidency,
		settingWebhookHost: o.WebhookHost,
	}
}

// settleSettings decides what an install runs with: what was given, else what
// the cluster was installed with. It returns the settings, the names of those
// taken from the cluster, and an error when a trust setting was given that
// differs from the cluster's and the change was not allowed.
func settleSettings(given, installed map[string]string, allowTrustChange bool) (map[string]string, []string, error) {
	settled := map[string]string{}
	var kept, refused []string
	for name, value := range given {
		was := installed[name]
		switch {
		case value == "" && was != "":
			settled[name] = was
			kept = append(kept, name)
		case value != "" && was != "" && value != was && slices.Contains(trustSettings, name) && !allowTrustChange:
			refused = append(refused, name)
		default:
			settled[name] = value
		}
	}
	slices.Sort(kept)
	if len(refused) > 0 {
		slices.Sort(refused)
		var b strings.Builder
		b.WriteString("this cluster was installed with different settings, and changing them replaces what it trusts:\n")
		for _, name := range refused {
			fmt.Fprintf(&b, "  --%s is %q here, not %q. Changing it replaces %s.\n",
				name, installed[name], given[name], whatChanging[name])
		}
		b.WriteString("Nothing signed before the change verifies after it. Leave the flag out to keep what the cluster has,\n" +
			"or add --allow-trust-change to make the change on purpose.")
		return nil, nil, fmt.Errorf("%s", b.String())
	}
	return settled, kept, nil
}

// installedSettings reads what the cluster was installed with. A cluster
// from before this was recorded is read from what is running on it.
func (i *Installer) installedSettings(ctx context.Context) map[string]string {
	installed := map[string]string{}
	if cm, err := i.dynamic.Resource(configMapGVR).Namespace(settingsNamespace).
		Get(ctx, settingsConfigMap, metav1.GetOptions{}); err == nil {
		data, _, _ := unstructured.NestedStringMap(cm.Object, "data")
		maps.Copy(installed, data)
	}
	for name, detect := range map[string]func(context.Context) string{
		settingResidency:   i.runningKeyResidency,
		settingIdentity:    i.runningSigningIdentity,
		settingTrustDomain: i.runningTrustDomain,
	} {
		if installed[name] == "" {
			installed[name] = detect(ctx)
		}
	}
	return installed
}

// runningKeyResidency tells where the signing keys are from how Fulcio is
// started. It is empty when Fulcio is not installed.
func (i *Installer) runningKeyResidency(ctx context.Context) string {
	fulcio, err := i.dynamic.Resource(deploymentGVR).Namespace(fulcioNamespace).Get(ctx, "fulcio-server", metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return residencyOf(fulcio)
}

// residencyOf reads the residency from Fulcio's Deployment.
func residencyOf(fulcio *unstructured.Unstructured) string {
	containers, _, _ := unstructured.NestedSlice(fulcio.Object, "spec", "template", "spec", "containers")
	for _, c := range containers {
		container, _ := c.(map[string]any)
		for _, arg := range stringsOf(container["args"]) {
			switch arg {
			case "--ca=kmsca":
				return ResidencyVault
			case "--ca=fileca":
				return ResidencyCluster
			}
		}
	}
	return ""
}

// runningSigningIdentity tells the signing identity from Chains' signing
// configuration, which is where the operator reads it too.
func (i *Installer) runningSigningIdentity(ctx context.Context) string {
	cm, err := i.dynamic.Resource(configMapGVR).Namespace("tekton-chains").Get(ctx, "chains-config", metav1.GetOptions{})
	if err != nil {
		return ""
	}
	data, _, _ := unstructured.NestedStringMap(cm.Object, "data")
	switch {
	case data["signers.x509.fulcio.provider"] == "spiffe":
		return IdentitySPIFFE
	case data["signers.x509.fulcio.issuer"] != "":
		return IdentityKubernetes
	}
	return ""
}

// runningTrustDomain reads the trust domain from Tekton's SPIRE
// configuration, where the installer records it.
func (i *Installer) runningTrustDomain(ctx context.Context) string {
	cm, err := i.dynamic.Resource(configMapGVR).Namespace("tekton-pipelines").Get(ctx, "config-spire", metav1.GetOptions{})
	if err != nil {
		return ""
	}
	domain, _, _ := unstructured.NestedString(cm.Object, "data", "spire-trust-domain")
	if domain == trustDomainPlaceholder || !trustDomainPattern.MatchString(domain) {
		return ""
	}
	return domain
}

// settle makes the install run with the cluster's own settings where none
// were given, refuses a change of what the cluster trusts that was not asked
// for, and records what it ends up with.
func (i *Installer) settle(ctx context.Context) error {
	settled, kept, err := settleSettings(i.given.givenSettings(), i.installedSettings(ctx), i.opts.AllowTrustChange)
	if err != nil {
		return err
	}
	i.opts.SigningIdentity = settled[settingIdentity]
	i.opts.TrustDomain = settled[settingTrustDomain]
	i.opts.KeyResidency = settled[settingResidency]
	if host := settled[settingWebhookHost]; host != "" {
		i.opts.WebhookHost, i.webhookHost = host, host
	}
	if err := i.opts.defaultAndValidate(); err != nil {
		return err
	}
	if len(kept) > 0 {
		values := make([]string, 0, len(kept))
		for _, name := range kept {
			values = append(values, "--"+name+" "+settled[name])
		}
		fmt.Printf("   Kept from this cluster's install: %s\n", strings.Join(values, ", "))
	}
	record := map[string]any{
		settingIdentity:    i.opts.SigningIdentity,
		settingTrustDomain: i.opts.TrustDomain,
		settingResidency:   i.opts.KeyResidency,
	}
	if i.webhookHost != "" {
		record[settingWebhookHost] = i.webhookHost
	}
	return i.applyObject(ctx, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name": settingsConfigMap, "namespace": settingsNamespace,
			"labels": map[string]any{"blanketops.dev/managed": "true"},
		},
		"data": record,
	}})
}
