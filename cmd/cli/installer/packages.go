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
	"fmt"
	"sort"
	"strings"
)

// Per-package install. The install steps are already a named, ordered list;
// these let the CLI name one (or a few) of them to apply on their own, so a
// single dependency can be installed or repaired without the whole run. No
// prerequisites are pulled in: a step that needs another to be up already
// will fail fast in its own pre-hook, exactly as --only-step does.

// slug is the typeable form of a step name: lowercased, spaces to hyphens.
// "MetalLB Install" -> "metallb-install", "Fulcio" -> "fulcio".
func slug(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), " ", "-")
}

// StepNames lists the installable steps for this install, in order and after
// the identity's Skip rules, as the names `install <name>` accepts. The Images
// pull-ahead step is left out: it applies nothing of its own.
func (i *Installer) StepNames() []string {
	var names []string
	for _, s := range installOrder {
		if s.PullsImages {
			continue
		}
		if s.Skip == nil || !s.Skip(i) {
			names = append(names, s.Name)
		}
	}
	return names
}

// resolveStep matches one user-given token to a step name. It accepts the
// exact name, its slug, or a unique prefix of the slug, all case-insensitively,
// so `fulcio`, `Fulcio` and `metallb-install` all resolve. An ambiguous token
// (for example `metallb`, which could be install or dependencies) is an error
// that lists the candidates; an unknown one lists every step.
func (i *Installer) resolveStep(token string) (string, error) {
	want := slug(token)
	names := i.StepNames()

	for _, n := range names {
		if slug(n) == want {
			return n, nil
		}
	}

	var matches []string
	for _, n := range names {
		if strings.HasPrefix(slug(n), want) {
			matches = append(matches, n)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no step %q; the steps are: %s", token, strings.Join(slugs(names), ", "))
	default:
		sort.Strings(matches)
		return "", fmt.Errorf("%q matches more than one step: %s — name one exactly",
			token, strings.Join(slugs(matches), ", "))
	}
}

// resolveSteps maps every requested token to a canonical step name, failing on
// the first that does not resolve. Duplicates are dropped, order preserved.
func (i *Installer) resolveSteps(tokens []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, t := range tokens {
		name, err := i.resolveStep(t)
		if err != nil {
			return nil, err
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

func slugs(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, slug(n))
	}
	return out
}

// SelectSteps resolves the user-given tokens to step names and sets the
// installer to apply exactly those, in installOrder. With no tokens it is a
// no-op and a normal full install follows.
func (i *Installer) SelectSteps(tokens []string) error {
	if len(tokens) == 0 {
		return nil
	}
	names, err := i.resolveSteps(tokens)
	if err != nil {
		return err
	}
	i.opts.OnlySteps = names
	return nil
}
