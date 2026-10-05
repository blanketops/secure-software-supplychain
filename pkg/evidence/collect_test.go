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

package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	testIssuer    = "http://oidc.spire.svc"
	buildSubject  = "spiffe://blanketops.dev/ns/default/sa/supply-chain-runner"
	chainsSubject = "spiffe://blanketops.dev/ns/tekton-chains/sa/tekton-chains-controller"
	testDigest    = "sha256:edb16307d4c188df67b8613298a514703e4d895d4c256a06b77a29bc58e459ea"
	testLogID     = "41550e896b69c2284b827f0b59c01fc7b826d098b8e9f19c418f485aa9c913be"
)

// signingCert makes a certificate shaped like the ones Fulcio issues: the
// identity as a URI SAN and the OIDC issuer in Fulcio's extension.
func signingCert(t *testing.T, subject string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(subject)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := asn1.Marshal(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(9 * time.Minute),
		URIs:            []*url.URL{uri},
		ExtraExtensions: []pkix.Extension{{Id: oidIssuerV2, Value: issuer}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// fakeRekor serves the two Rekor calls the collector makes. entries maps an
// index key to the entries logged under it.
type fakeRekor struct {
	entries map[string][]map[string]any
	byUUID  map[string]map[string]any
}

func newFakeRekor() *fakeRekor {
	return &fakeRekor{entries: map[string][]map[string]any{}, byUUID: map[string]map[string]any{}}
}

func (f *fakeRekor) add(hash string, index int64, body map[string]any) {
	raw, _ := json.Marshal(body)
	uuid := fmt.Sprintf("uuid-%d", index)
	entry := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(raw),
		"integratedTime": 1791236744 + index,
		"logID":          testLogID,
		"logIndex":       index,
	}
	f.entries[hash] = append(f.entries[hash], map[string]any{uuid: entry})
	f.byUUID[uuid] = entry
}

func (f *fakeRekor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Hash       string   `json:"hash"`
		EntryUUIDs []string `json:"entryUUIDs"`
	}
	_ = json.NewDecoder(r.Body).Decode(&request)
	switch r.URL.Path {
	case "/api/v1/index/retrieve":
		uuids := []string{}
		for _, entry := range f.entries[request.Hash] {
			for uuid := range entry {
				uuids = append(uuids, uuid)
			}
		}
		_ = json.NewEncoder(w).Encode(uuids)
	case "/api/v1/log/entries/retrieve":
		found := []map[string]any{}
		for _, uuid := range request.EntryUUIDs {
			found = append(found, map[string]any{uuid: f.byUUID[uuid]})
		}
		_ = json.NewEncoder(w).Encode(found)
	default:
		http.NotFound(w, r)
	}
}

type layerSpec struct {
	content     []byte
	mediaType   types.MediaType
	annotations map[string]string
}

func push(t *testing.T, tag name.Tag, layers ...layerSpec) {
	t.Helper()
	image := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	for _, l := range layers {
		var err error
		image, err = mutate.Append(image, mutate.Addendum{
			Layer:       static.NewLayer(l.content, l.mediaType),
			Annotations: l.annotations,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := remote.Write(tag, image); err != nil {
		t.Fatal(err)
	}
}

func envelope(t *testing.T, predicateType string) (blob []byte, payloadHash string) {
	t.Helper()
	statement, _ := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predicateType,
		"subject":       []any{map[string]any{"name": "app", "digest": map[string]string{"sha256": testDigest[7:]}}},
	})
	sum := sha256.Sum256(statement)
	blob, _ = json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []any{map[string]string{"sig": "c2ln"}},
	})
	return blob, hex.EncodeToString(sum[:])
}

func layerDigest(t *testing.T, content []byte) string {
	t.Helper()
	h, _, err := v1.SHA256(strings.NewReader(string(content)))
	if err != nil {
		t.Fatal(err)
	}
	return h.String()
}

// The image carries what a real two-tier build leaves behind: Chains' and the
// build's signature, Chains' provenance and the build's authorization
// attestation. cosign (the build) stores Rekor's answer with what it signs;
// Chains does not, so its entries have to be found in the log.
func TestCollect(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	defer reg.Close()
	log := newFakeRekor()
	rekorServer := httptest.NewServer(log)
	defer rekorServer.Close()

	repo, err := name.NewRepository(strings.TrimPrefix(reg.URL, "http://") + "/org/app")
	if err != nil {
		t.Fatal(err)
	}
	tagFor := func(suffix string) name.Tag {
		return repo.Tag(strings.Replace(testDigest, ":", "-", 1) + "." + suffix)
	}
	bundle := func(index int64) string {
		raw, _ := json.Marshal(map[string]any{
			"SignedEntryTimestamp": "c2V0",
			"Payload": map[string]any{
				"body": "", "integratedTime": 1791236744 + index, "logIndex": index, "logID": testLogID,
			},
		})
		return string(raw)
	}

	chainsCert, buildCert := signingCert(t, chainsSubject), signingCert(t, buildSubject)
	payload := []byte(`{"critical":{"image":{"docker-manifest-digest":"` + testDigest + `"}}}`)
	// Both sign the same payload, so the log holds two entries under its
	// hash; only the signature tells them apart.
	log.add(layerDigest(t, payload), 32, map[string]any{
		"kind": "hashedrekord", "spec": map[string]any{"signature": map[string]any{"content": "chains-signature"}},
	})
	log.add(layerDigest(t, payload), 33, map[string]any{
		"kind": "hashedrekord", "spec": map[string]any{"signature": map[string]any{"content": "build-signature"}},
	})
	push(t, tagFor("sig"),
		layerSpec{payload, "application/vnd.dev.cosign.simplesigning.v1+json", map[string]string{
			annotationSignature: "chains-signature", annotationCertificate: chainsCert,
		}},
		layerSpec{payload, "application/vnd.dev.cosign.simplesigning.v1+json", map[string]string{
			annotationSignature: "build-signature", annotationCertificate: buildCert, annotationBundle: bundle(33),
		}},
	)

	provenance, provenanceHash := envelope(t, "https://slsa.dev/provenance/v1")
	authorization, _ := envelope(t, "https://blanketops.dev/attestations/authorization/v1")
	log.add("sha256:"+provenanceHash, 31, map[string]any{
		"kind": "intoto", "spec": map[string]any{"content": map[string]any{"payloadHash": map[string]any{"value": provenanceHash}}},
	})
	push(t, tagFor("att"),
		layerSpec{provenance, "application/vnd.dsse.envelope.v1+json", map[string]string{annotationCertificate: chainsCert}},
		layerSpec{authorization, "application/vnd.dsse.envelope.v1+json", map[string]string{
			annotationCertificate: buildCert, annotationBundle: bundle(34),
		}},
	)

	records, err := Collect(context.Background(), Options{
		Image:         repo.String() + ":v1",
		Digest:        testDigest,
		RekorURL:      rekorServer.URL,
		BuildSubject:  buildSubject,
		ChainsSubject: chainsSubject,
	})
	if err != nil {
		t.Fatal(err)
	}

	type summary struct {
		index                         int64
		kind, signedBy, predicateType string
	}
	want := []summary{
		{31, KindAttestation, SignedByChains, "https://slsa.dev/provenance/v1"},
		{32, KindSignature, SignedByChains, ""},
		{33, KindSignature, SignedByBuild, ""},
		{34, KindAttestation, SignedByBuild, "https://blanketops.dev/attestations/authorization/v1"},
	}
	if len(records) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(records), len(want), records)
	}
	for i, w := range want {
		r := records[i]
		if r.RekorLogIndex == nil {
			t.Fatalf("record %d has no log index: %+v", i, r)
		}
		if got := (summary{*r.RekorLogIndex, r.Kind, r.SignedBy, r.PredicateType}); got != w {
			t.Errorf("record %d = %+v, want %+v", i, got, w)
		}
		if r.Issuer != testIssuer || r.RekorLogID != testLogID || r.IntegratedAt == nil {
			t.Errorf("record %d: issuer %q, log %q, integratedAt %v", i, r.Issuer, r.RekorLogID, r.IntegratedAt)
		}
		if !strings.HasPrefix(r.KeyFingerprint, "sha256:") || !strings.HasPrefix(r.CertificateFingerprint, "sha256:") ||
			r.KeyFingerprint == r.CertificateFingerprint || r.NotBefore == nil || r.NotAfter == nil {
			t.Errorf("record %d: key %q, certificate %q", i, r.KeyFingerprint, r.CertificateFingerprint)
		}
	}
	// One certificate, and so one key, per signer.
	if records[1].KeyFingerprint != records[0].KeyFingerprint || records[1].KeyFingerprint == records[2].KeyFingerprint {
		t.Errorf("key fingerprints do not follow the signers: %q %q %q",
			records[0].KeyFingerprint, records[1].KeyFingerprint, records[2].KeyFingerprint)
	}
}

// A signature that is not in the log is still evidence that someone signed;
// it is reported, without an index, and the error says the entry is missing.
func TestCollectReportsWhatTheLogDoesNotHave(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	defer reg.Close()
	rekorServer := httptest.NewServer(newFakeRekor())
	defer rekorServer.Close()

	repo, _ := name.NewRepository(strings.TrimPrefix(reg.URL, "http://") + "/org/app")
	push(t, repo.Tag(strings.Replace(testDigest, ":", "-", 1)+".sig"),
		layerSpec{[]byte("payload"), "application/vnd.dev.cosign.simplesigning.v1+json", map[string]string{
			annotationSignature: "signature", annotationCertificate: signingCert(t, "spiffe://elsewhere.example/ns/x/sa/y"),
		}},
	)

	records, err := Collect(context.Background(), Options{
		Image: repo.String(), Digest: testDigest, RekorURL: rekorServer.URL,
		BuildSubject: buildSubject, ChainsSubject: chainsSubject,
	})
	if err == nil || !strings.Contains(err.Error(), "no transparency log entry found") {
		t.Errorf("err = %v, want it to say the log entry is missing", err)
	}
	if len(records) != 1 || records[0].RekorLogIndex != nil || records[0].SignedBy != SignedByOther {
		t.Fatalf("records = %+v, want the one signature, by Other, without an index", records)
	}
}

// An image nobody signed has no evidence, and that is not an error.
func TestCollectUnsignedImage(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	defer reg.Close()
	repo, _ := name.NewRepository(strings.TrimPrefix(reg.URL, "http://") + "/org/app")

	records, err := Collect(context.Background(), Options{
		Image: repo.String(), Digest: testDigest, RekorURL: "http://unused",
	})
	if err != nil || len(records) != 0 {
		t.Errorf("records = %v, err = %v; want none and no error", records, err)
	}
}
