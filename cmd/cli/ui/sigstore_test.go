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

package ui

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testSubject = "spiffe://your-domain.example/ns/default/sa/supply-chain-runner"
	testIssuer  = "https://spire-spiffe-oidc-discovery-provider.spire-server.svc.cluster.local"
)

// signingCert makes a certificate as Fulcio issues them: for a SPIFFE ID,
// with the identity provider that vouched for it in an extension.
func signingCert(t *testing.T, isCA bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := asn1.Marshal(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := url.Parse(testSubject)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0x2a),
		Subject:               pkix.Name{CommonName: "fulcio"},
		NotBefore:             time.Unix(1_800_000_000, 0),
		NotAfter:              time.Unix(1_800_000_600, 0),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if !isCA {
		template.Subject = pkix.Name{}
		template.URIs = []*url.URL{subject}
		template.ExtraExtensions = []pkix.Extension{{Id: oidFulcioIssuerV2, Value: issuer}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// fakeCluster is the Kubernetes API as kubectl proxy serves it, with Rekor,
// Fulcio and the CT log behind its Service proxy.
type fakeCluster struct {
	t         *testing.T
	entries   map[int64]map[string]any // by log index
	rekorKey  string
	fulcioCA  string
	anchors   map[string]string
	retrieved [][]int64
	requests  []string
}

func b64(v any) string {
	data, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(data)
}

func (f *fakeCluster) add(index int64, uuid string, body map[string]any) {
	f.entries[index] = map[string]any{uuid: map[string]any{
		"body": b64(body), "integratedTime": 1_800_000_100 + index, "logIndex": index,
		"verification": map[string]any{
			"inclusionProof":       map[string]any{"treeSize": len(f.entries) + 1},
			"signedEntryTimestamp": "c2V0",
		},
	}}
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	rekor := "/api/v1/namespaces/rekor-system/services/https:rekor-server:443/proxy"
	fulcio := "/api/v1/namespaces/fulcio-system/services/https:fulcio-server:443/proxy"
	ctlog := "/api/v1/namespaces/ctlog-system/services/https:ctlog:443/proxy/fulcio"
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch path := r.URL.Path; {
	case path == "/api/v1/namespaces/default/configmaps/"+trustAnchorsConfigMap:
		write(map[string]any{"data": f.anchors})
	case path == rekor+"/api/v1/log":
		write(map[string]any{"rootHash": "abc123", "treeSize": len(f.entries), "treeID": "7441"})
	case path == rekor+"/api/v1/log/publicKey":
		// As Rekor does: the PEM itself, or a JSON string of it when JSON
		// is what was asked for.
		if strings.Contains(r.Header.Get("Accept"), "json") {
			write(f.rekorKey)
			return
		}
		_, _ = w.Write([]byte(f.rekorKey))
	case path == rekor+"/api/v1/log/entries/retrieve":
		var in struct {
			LogIndexes []int64 `json:"logIndexes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if len(in.LogIndexes) > 10 {
			http.Error(w, "too many", http.StatusUnprocessableEntity)
			return
		}
		f.retrieved = append(f.retrieved, in.LogIndexes)
		out := []map[string]any{}
		for _, index := range in.LogIndexes {
			if entry, ok := f.entries[index]; ok {
				out = append(out, entry)
			}
		}
		write(out)
	case path == rekor+"/api/v1/log/entries" && r.URL.Query().Get("logIndex") != "":
		var index int64
		_, _ = fmt.Sscan(r.URL.Query().Get("logIndex"), &index)
		if entry, ok := f.entries[index]; ok {
			write(entry)
			return
		}
		http.NotFound(w, r)
	case strings.HasPrefix(path, rekor+"/api/v1/log/entries/"):
		for _, entry := range f.entries {
			if _, ok := entry[strings.TrimPrefix(path, rekor+"/api/v1/log/entries/")]; ok {
				write(entry)
				return
			}
		}
		http.NotFound(w, r)
	case path == rekor+"/api/v1/index/retrieve":
		var in struct {
			Hash string `json:"hash"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		uuids := []string{}
		if in.Hash == "sha256:"+strings.Repeat("a", 64) {
			uuids = append(uuids, strings.Repeat("1", 64))
		}
		write(uuids)
	case path == fulcio+"/api/v2/trustBundle":
		write(map[string]any{"chains": []any{map[string]any{"certificates": []string{f.fulcioCA}}}})
	case path == fulcio+"/api/v2/configuration":
		write(map[string]any{"issuers": []any{map[string]any{
			"issuerUrl": testIssuer, "audience": "sigstore", "issuerType": "spiffe",
			"spiffeTrustDomain": "your-domain.example",
		}}})
	case path == ctlog+"/ct/v1/get-sth":
		write(map[string]any{"tree_size": 12, "timestamp": 1_800_000_000_000, "sha256_root_hash": "AQID"})
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func newFakeCluster(t *testing.T) (*fakeCluster, *querier) {
	t.Helper()
	leaf := signingCert(t, false)
	root := signingCert(t, true)
	const key = "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n"
	fake := &fakeCluster{
		t: t, entries: map[int64]map[string]any{}, rekorKey: key, fulcioCA: root,
		anchors: map[string]string{"rekor.pub": key, "fulcio-root.pem": root},
	}
	verifier := base64.StdEncoding.EncodeToString([]byte(leaf))
	fake.add(0, strings.Repeat("1", 64), map[string]any{"kind": "hashedrekord", "spec": map[string]any{
		"data":      map[string]any{"hash": map[string]any{"algorithm": "sha256", "value": strings.Repeat("a", 64)}},
		"signature": map[string]any{"publicKey": map[string]any{"content": verifier}},
	}})
	fake.add(1, strings.Repeat("2", 64), map[string]any{"kind": "dsse", "spec": map[string]any{
		"payloadHash": map[string]any{"algorithm": "sha256", "value": strings.Repeat("b", 64)},
		"signatures":  []any{map[string]any{"verifier": verifier}},
	}})
	for index := int64(2); index < 23; index++ {
		fake.add(index, fmt.Sprintf("%064x", index+16), map[string]any{"kind": "intoto", "spec": map[string]any{
			"content":   map[string]any{"payloadHash": map[string]any{"value": strings.Repeat("c", 64)}},
			"publicKey": verifier,
		}})
	}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return fake, newQuerier(server.URL)
}

// The summary is what the services present, held against the trust anchors
// the pipeline and the admission policies verify with. A log or a CA that is
// not the one the cluster trusts has to show as such.
func TestSummaryChecksAgainstTheTrustAnchors(t *testing.T) {
	fake, q := newFakeCluster(t)
	summary := q.Summary(context.Background(), "default")

	if summary.Rekor.Error != "" || summary.Rekor.TreeSize != 23 || summary.Rekor.TreeID != "7441" {
		t.Errorf("rekor = %+v", summary.Rekor)
	}
	if summary.Rekor.Trusted == nil || !*summary.Rekor.Trusted {
		t.Error("the log's key is the trust anchor, and is not reported as trusted")
	}
	if len(summary.Fulcio.Roots) != 1 || summary.Fulcio.Roots[0].Trusted == nil || !*summary.Fulcio.Roots[0].Trusted ||
		!summary.Fulcio.Roots[0].IsCA {
		t.Errorf("fulcio roots = %+v", summary.Fulcio.Roots)
	}
	want := OIDCIssuer{URL: testIssuer, Audience: "sigstore", Kind: "spiffe", TrustDomain: "your-domain.example"}
	if len(summary.Fulcio.Issuers) != 1 || summary.Fulcio.Issuers[0] != want {
		t.Errorf("fulcio issuers = %+v, want %+v", summary.Fulcio.Issuers, want)
	}
	if summary.CTLog.TreeSize != 12 || summary.CTLog.RootHash != "010203" || summary.CTLog.Timestamp == nil {
		t.Errorf("ct log = %+v", summary.CTLog)
	}

	// Another log's key, another CA's root.
	other := signingCert(t, true)
	fake.anchors = map[string]string{
		"rekor.pub":       "-----BEGIN PUBLIC KEY-----\nBAUG\n-----END PUBLIC KEY-----\n",
		"fulcio-root.pem": other,
	}
	summary = q.Summary(context.Background(), "default")
	if summary.Rekor.Trusted == nil || *summary.Rekor.Trusted {
		t.Error("a log signing with another key is reported as trusted")
	}
	if summary.Fulcio.Roots[0].Trusted == nil || *summary.Fulcio.Roots[0].Trusted {
		t.Error("a CA with another root is reported as trusted")
	}

	// Without anchors there is nothing to compare with, which is not "no".
	fake.anchors = nil
	if summary = q.Summary(context.Background(), "default"); summary.Rekor.Trusted != nil {
		t.Error("with no trust anchor the log's key was still judged")
	}
}

// An entry says what was signed and by whom, from the certificate logged
// with it, whichever of the three kinds it is.
func TestEntriesAreDecoded(t *testing.T) {
	fake, q := newFakeCluster(t)
	page, err := q.Entries(context.Background(), 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if page.TreeSize != 23 || len(page.Entries) != 20 || page.Entries[0].LogIndex != 22 ||
		page.Entries[19].LogIndex != 3 || page.Next != 3 {
		t.Fatalf("page: tree %d, %d entries from %d, next %d; want the newest 20 and a next page at 3",
			page.TreeSize, len(page.Entries), page.Entries[0].LogIndex, page.Next)
	}
	for _, batch := range fake.retrieved {
		if len(batch) > 10 {
			t.Errorf("asked Rekor for %d entries at once; it returns at most 10", len(batch))
		}
	}

	last, err := q.Entries(context.Background(), page.Next, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(last.Entries) != 3 || last.Next != 0 {
		t.Fatalf("last page has %d entries and next %d, want 3 and none", len(last.Entries), last.Next)
	}
	signature, attestation := last.Entries[2], last.Entries[1]
	if signature.Kind != "hashedrekord" || signature.ArtifactHash != "sha256:"+strings.Repeat("a", 64) {
		t.Errorf("signature entry = %+v", signature)
	}
	if attestation.Kind != "dsse" || attestation.ArtifactHash != "sha256:"+strings.Repeat("b", 64) {
		t.Errorf("attestation entry = %+v", attestation)
	}
	for _, entry := range []Entry{signature, attestation, last.Entries[0]} {
		if entry.Subject != testSubject || entry.Issuer != testIssuer || entry.CertSerial != "2a" ||
			entry.CertNotAfter == nil || !entry.InclusionProof || !entry.SignedTimestamp || entry.IntegratedTime == nil {
			t.Errorf("entry %d does not say who signed or that it is proven: %+v", entry.LogIndex, entry)
		}
	}
}

// What is searched for becomes part of a request to the Kubernetes API, so
// only the three forms an entry can be named by are let through.
func TestSearch(t *testing.T) {
	fake, q := newFakeCluster(t)
	ctx := context.Background()
	for term, want := range map[string]int64{
		"1":                                 1,
		"sha256:" + strings.Repeat("a", 64): 0,
		strings.Repeat("A", 64):             0, // a digest, in capitals
		strings.Repeat("2", 64):             1, // an entry's UUID
	} {
		entries, err := q.Search(ctx, " "+term+" ")
		if err != nil || len(entries) != 1 || entries[0].LogIndex != want {
			t.Errorf("Search(%q) = %+v, %v; want entry %d", term, entries, err, want)
		}
	}
	if entries, err := q.Search(ctx, "999"); err != nil || len(entries) != 0 {
		t.Errorf("an index that is not in the log returned %+v, %v; want nothing and no error", entries, err)
	}

	before := len(fake.requests)
	for _, term := range []string{"", "../../secrets", "1/../../../namespaces/vault/secrets/vault-unseal",
		"sha256:xyz", "1?x=y", strings.Repeat("a", 63)} {
		if _, err := q.Search(ctx, term); err == nil {
			t.Errorf("Search(%q) was accepted", term)
		}
	}
	if len(fake.requests) != before {
		t.Errorf("a refused search still reached the cluster: %v", fake.requests[before:])
	}
}

func TestHandler(t *testing.T) {
	_, q := newFakeCluster(t)
	server := httptest.NewServer(q.handler())
	defer server.Close()

	get := func(path string, out any) int {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if out != nil {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}
		return resp.StatusCode
	}
	var summary Summary
	if code := get("/sigstore/summary", &summary); code != http.StatusOK || summary.Rekor.TreeSize != 23 {
		t.Errorf("summary: %d %+v", code, summary.Rekor)
	}
	var page EntryPage
	if code := get("/sigstore/entries?limit=5", &page); code != http.StatusOK || len(page.Entries) != 5 {
		t.Errorf("entries: %d, %d entries", code, len(page.Entries))
	}
	var found struct {
		Entries []Entry `json:"entries"`
	}
	if code := get("/sigstore/search?q=0", &found); code != http.StatusOK || len(found.Entries) != 1 {
		t.Errorf("search: %d, %d entries", code, len(found.Entries))
	}
	if code := get("/sigstore/search?q=..%2F..", nil); code != http.StatusBadRequest {
		t.Errorf("a search that is not an index, UUID or digest answered %d", code)
	}
	if code := get("/sigstore/summary?namespace=..%2Fkube-system", nil); code != http.StatusBadRequest {
		t.Errorf("a namespace that is not a name answered %d", code)
	}
}

// A service that is not running is reported in the Kubernetes API's own
// words, and one part being down does not hide the others.
func TestSummaryWhenAServiceIsDown(t *testing.T) {
	_, q := newFakeCluster(t)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/rekor-system/") {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"no endpoints available for service \"rekor-server\""}`))
			return
		}
		resp, err := http.Get(q.kube + r.URL.RequestURI())
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer down.Close()

	summary := newQuerier(down.URL).Summary(context.Background(), "default")
	if summary.Rekor.Error != `no endpoints available for service "rekor-server"` {
		t.Errorf("rekor error = %q", summary.Rekor.Error)
	}
	if summary.Fulcio.Error != "" || len(summary.Fulcio.Roots) != 1 || summary.CTLog.TreeSize != 12 {
		t.Errorf("the other services were not read: fulcio %+v, ct log %+v", summary.Fulcio, summary.CTLog)
	}
}
