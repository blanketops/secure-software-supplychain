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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The observer shows what the transparency log and the certificate authority
// themselves say, next to what the cluster's resources record about them. It
// reaches Rekor, Fulcio and the CT log the way it reaches everything else:
// through the Kubernetes API, which proxies to a Service. Nothing here needs
// an address inside the cluster or a credential of its own.
//
// The API server does not verify a Service's certificate when it proxies, so
// what is read here is checked against the trust anchors instead: the log's
// public key and Fulcio's root are compared with the ones the pipeline and the
// admission policies verify against.

// sigstoreService is one of the in-cluster services, as the Kubernetes API
// proxies to it.
type sigstoreService struct {
	Namespace, Name string
	// Prefix is the path the service's API starts at.
	Prefix string
	// URL is the address workloads in the cluster use, for display.
	URL string
}

var (
	rekorService = sigstoreService{
		Namespace: "rekor-system", Name: "rekor-server",
		URL: "https://rekor-server.rekor-system.svc.cluster.local",
	}
	fulcioService = sigstoreService{
		Namespace: "fulcio-system", Name: "fulcio-server",
		URL: "https://fulcio-server.fulcio-system.svc.cluster.local",
	}
	ctLogService = sigstoreService{
		Namespace: "ctlog-system", Name: "ctlog", Prefix: "/fulcio",
		URL: "https://ctlog.ctlog-system.svc/fulcio",
	}
)

const (
	trustAnchorsConfigMap = "blanketops-sigstore-roots"
	// maxEntries bounds one page of log entries; Rekor returns at most ten
	// per request, so a page is a few requests.
	maxEntries = 50
)

// Fulcio records the OIDC issuer of the identity it certified in these
// extensions: the first as a raw string, the second, which replaces it, as a
// DER-encoded one.
var (
	oidFulcioIssuer   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// What may be searched for. Each form goes into a request path, so nothing
// else is let through.
var (
	digestPattern = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{64}([0-9a-f]{16})?$`)
	indexPattern  = regexp.MustCompile(`^[0-9]{1,18}$`)
	nsPattern     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

// querier asks Rekor, Fulcio and the CT log through the Kubernetes API.
type querier struct {
	// kube is the address of the Kubernetes API, as kubectl proxy serves it.
	kube string
	http *http.Client
}

func newQuerier(kube string) *querier {
	return &querier{kube: strings.TrimRight(kube, "/"), http: &http.Client{Timeout: 20 * time.Second}}
}

// serviceURL is the Kubernetes API path that proxies to a service's HTTPS
// port.
func (q *querier) serviceURL(svc sigstoreService, path string) string {
	return fmt.Sprintf("%s/api/v1/namespaces/%s/services/https:%s:443/proxy%s%s",
		q.kube, svc.Namespace, svc.Name, svc.Prefix, path)
}

func (q *querier) do(ctx context.Context, method, url string, in any) ([]byte, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := q.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// When the service is not running the answer comes from the
		// Kubernetes API, which says why in its own words.
		var status struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &status) == nil && status.Kind == "Status" && status.Message != "" {
			return nil, errors.New(status.Message)
		}
		return nil, fmt.Errorf("%s", strings.TrimSpace(resp.Status+" "+firstLine(data)))
	}
	return data, nil
}

var errNotFound = errors.New("not found")

func firstLine(data []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
	if len(line) > 160 {
		line = line[:160]
	}
	return line
}

func (q *querier) get(ctx context.Context, svc sigstoreService, path string, out any) error {
	data, err := q.do(ctx, http.MethodGet, q.serviceURL(svc, path), nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// ── What is reported ─────────────────────────────────────────────────────────

// Summary is the state of the transparency log, the certificate authority and
// the certificate transparency log, each checked against the trust anchors.
type Summary struct {
	Rekor  LogSummary `json:"rekor"`
	Fulcio CASummary  `json:"fulcio"`
	CTLog  CTSummary  `json:"ctLog"`
	// TrustAnchors is where the anchors were read from, or why they could
	// not be.
	TrustAnchors string `json:"trustAnchors"`
}

// LogSummary is Rekor's signed description of itself.
type LogSummary struct {
	URL      string `json:"url"`
	TreeSize int64  `json:"treeSize"`
	RootHash string `json:"rootHash,omitempty"`
	TreeID   string `json:"treeID,omitempty"`
	// KeyFingerprint is the SHA-256 of the key the log signs with.
	KeyFingerprint string `json:"keyFingerprint,omitempty"`
	// Trusted is whether that key is the one in the trust anchors. Nil when
	// there was nothing to compare with.
	Trusted *bool  `json:"trusted,omitempty"`
	Error   string `json:"error,omitempty"`
}

// CASummary is Fulcio's root and whose identities it certifies.
type CASummary struct {
	URL     string       `json:"url"`
	Roots   []CertInfo   `json:"roots,omitempty"`
	Issuers []OIDCIssuer `json:"issuers,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// CertInfo is what matters of a certificate, for showing.
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprint"`
	IsCA        bool      `json:"isCA"`
	Trusted     *bool     `json:"trusted,omitempty"`
}

// OIDCIssuer is an identity provider Fulcio issues certificates for.
type OIDCIssuer struct {
	URL         string `json:"url"`
	Audience    string `json:"audience,omitempty"`
	Kind        string `json:"kind,omitempty"`
	TrustDomain string `json:"trustDomain,omitempty"`
}

// CTSummary is the certificate transparency log's signed tree head. Its size
// is the number of certificates Fulcio has issued.
type CTSummary struct {
	URL       string     `json:"url"`
	TreeSize  int64      `json:"treeSize"`
	RootHash  string     `json:"rootHash,omitempty"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// Entry is one transparency log entry, decoded.
type Entry struct {
	LogIndex int64  `json:"logIndex"`
	UUID     string `json:"uuid"`
	// Kind is what was logged: hashedrekord for a signature, dsse or intoto
	// for an attestation.
	Kind           string     `json:"kind"`
	IntegratedTime *time.Time `json:"integratedTime,omitempty"`
	// ArtifactHash is the digest of what was signed: for an image signature,
	// of the signed payload that names the image, not of the image.
	ArtifactHash string `json:"artifactHash,omitempty"`
	// Who signed, from the certificate Fulcio issued for the signature.
	Subject       string     `json:"subject,omitempty"`
	Issuer        string     `json:"issuer,omitempty"`
	CertNotBefore *time.Time `json:"certNotBefore,omitempty"`
	CertNotAfter  *time.Time `json:"certNotAfter,omitempty"`
	CertSerial    string     `json:"certSerial,omitempty"`
	// InclusionProof is whether the log returned a proof that the entry is
	// in the tree; ProofTreeSize is the size of the tree it is a proof for.
	InclusionProof bool  `json:"inclusionProof"`
	ProofTreeSize  int64 `json:"proofTreeSize,omitempty"`
	// SignedTimestamp is whether the log signed its promise to include it.
	SignedTimestamp bool `json:"signedTimestamp"`
}

// EntryPage is a page of entries, newest first.
type EntryPage struct {
	TreeSize int64   `json:"treeSize"`
	Entries  []Entry `json:"entries"`
	// Next is the log index to pass as "before" for the page after this
	// one. Zero when this is the last.
	Next int64 `json:"next,omitempty"`
}

// ── Queries ──────────────────────────────────────────────────────────────────

// Summary reads the three services and compares what they present with the
// trust anchors in namespace.
func (q *querier) Summary(ctx context.Context, namespace string) Summary {
	anchors, anchorsErr := q.trustAnchors(ctx, namespace)
	summary := Summary{TrustAnchors: namespace + "/" + trustAnchorsConfigMap}
	if anchorsErr != nil {
		summary.TrustAnchors = "not read: " + anchorsErr.Error()
	}
	summary.Rekor = q.rekorSummary(ctx, anchors["rekor.pub"])
	summary.Fulcio = q.fulcioSummary(ctx, anchors["fulcio-root.pem"])
	summary.CTLog = q.ctLogSummary(ctx)
	return summary
}

func (q *querier) trustAnchors(ctx context.Context, namespace string) (map[string]string, error) {
	data, err := q.do(ctx, http.MethodGet,
		fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps/%s", q.kube, namespace, trustAnchorsConfigMap), nil)
	if err != nil {
		return nil, err
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(data, &cm); err != nil {
		return nil, err
	}
	return cm.Data, nil
}

func (q *querier) rekorLog(ctx context.Context) (treeSize int64, rootHash, treeID string, err error) {
	var log struct {
		RootHash string `json:"rootHash"`
		TreeSize int64  `json:"treeSize"`
		TreeID   string `json:"treeID"`
	}
	if err := q.get(ctx, rekorService, "/api/v1/log", &log); err != nil {
		return 0, "", "", err
	}
	return log.TreeSize, log.RootHash, log.TreeID, nil
}

func (q *querier) rekorSummary(ctx context.Context, anchor string) LogSummary {
	out := LogSummary{URL: rekorService.URL}
	var err error
	if out.TreeSize, out.RootHash, out.TreeID, err = q.rekorLog(ctx); err != nil {
		out.Error = err.Error()
		return out
	}
	key, err := q.do(ctx, http.MethodGet, q.serviceURL(rekorService, "/api/v1/log/publicKey"), nil)
	if err != nil {
		out.Error = "public key: " + err.Error()
		return out
	}
	// Asked for JSON, Rekor answers with the PEM as a JSON string.
	var quoted string
	if json.Unmarshal(key, &quoted) == nil && quoted != "" {
		key = []byte(quoted)
	}
	out.KeyFingerprint = fingerprint(key)
	if strings.TrimSpace(anchor) != "" {
		trusted := out.KeyFingerprint == fingerprint([]byte(anchor))
		out.Trusted = &trusted
	}
	return out
}

func (q *querier) fulcioSummary(ctx context.Context, anchor string) CASummary {
	out := CASummary{URL: fulcioService.URL}
	var bundle struct {
		Chains []struct {
			Certificates []string `json:"certificates"`
		} `json:"chains"`
	}
	if err := q.get(ctx, fulcioService, "/api/v2/trustBundle", &bundle); err != nil {
		out.Error = err.Error()
		return out
	}
	trusted := map[string]bool{}
	for _, cert := range parseCertificates([]byte(anchor)) {
		trusted[fingerprint(cert.Raw)] = true
	}
	for _, chain := range bundle.Chains {
		for _, encoded := range chain.Certificates {
			for _, cert := range parseCertificates([]byte(encoded)) {
				info := certInfo(cert)
				if len(trusted) > 0 {
					is := trusted[info.Fingerprint]
					info.Trusted = &is
				}
				out.Roots = append(out.Roots, info)
			}
		}
	}

	var config struct {
		Issuers []struct {
			IssuerURL         string `json:"issuerUrl"`
			WildcardIssuerURL string `json:"wildcardIssuerUrl"`
			Audience          string `json:"audience"`
			IssuerType        string `json:"issuerType"`
			SpiffeTrustDomain string `json:"spiffeTrustDomain"`
		} `json:"issuers"`
	}
	if err := q.get(ctx, fulcioService, "/api/v2/configuration", &config); err != nil {
		out.Error = "configuration: " + err.Error()
		return out
	}
	for _, issuer := range config.Issuers {
		url := issuer.IssuerURL
		if url == "" {
			url = issuer.WildcardIssuerURL
		}
		out.Issuers = append(out.Issuers, OIDCIssuer{
			URL: url, Audience: issuer.Audience, Kind: issuer.IssuerType, TrustDomain: issuer.SpiffeTrustDomain,
		})
	}
	return out
}

func (q *querier) ctLogSummary(ctx context.Context) CTSummary {
	out := CTSummary{URL: ctLogService.URL}
	var sth struct {
		TreeSize  int64  `json:"tree_size"`
		Timestamp int64  `json:"timestamp"`
		RootHash  string `json:"sha256_root_hash"`
	}
	if err := q.get(ctx, ctLogService, "/ct/v1/get-sth", &sth); err != nil {
		out.Error = err.Error()
		return out
	}
	out.TreeSize = sth.TreeSize
	if raw, err := base64.StdEncoding.DecodeString(sth.RootHash); err == nil {
		out.RootHash = hex.EncodeToString(raw)
	}
	if sth.Timestamp > 0 {
		at := time.UnixMilli(sth.Timestamp).UTC()
		out.Timestamp = &at
	}
	return out
}

// Entries returns up to limit entries older than before, newest first. A
// before of zero starts at the newest.
func (q *querier) Entries(ctx context.Context, before int64, limit int) (EntryPage, error) {
	treeSize, _, _, err := q.rekorLog(ctx)
	if err != nil {
		return EntryPage{}, err
	}
	page := EntryPage{TreeSize: treeSize, Entries: []Entry{}}
	if limit <= 0 || limit > maxEntries {
		limit = maxEntries
	}
	if before <= 0 || before > treeSize {
		before = treeSize
	}
	first := max(before-int64(limit), 0)
	// Rekor returns at most ten entries for one request.
	for end := before; end > first; end -= 10 {
		var indexes []int64
		for index := end - 1; index >= max(end-10, first); index-- {
			indexes = append(indexes, index)
		}
		data, err := q.do(ctx, http.MethodPost, q.serviceURL(rekorService, "/api/v1/log/entries/retrieve"),
			map[string]any{"logIndexes": indexes})
		if err != nil {
			return page, err
		}
		var found []map[string]rawEntry
		if err := json.Unmarshal(data, &found); err != nil {
			return page, err
		}
		for _, byUUID := range found {
			for uuid, raw := range byUUID {
				page.Entries = append(page.Entries, decodeEntry(uuid, raw))
			}
		}
	}
	sort.Slice(page.Entries, func(a, b int) bool { return page.Entries[a].LogIndex > page.Entries[b].LogIndex })
	if first > 0 {
		page.Next = first
	}
	return page, nil
}

// Search finds entries by what the user has: a log index, an entry's UUID, or
// the SHA-256 of what was signed.
func (q *querier) Search(ctx context.Context, term string) ([]Entry, error) {
	term = strings.ToLower(strings.TrimSpace(term))
	switch {
	case indexPattern.MatchString(term):
		var byUUID map[string]rawEntry
		if err := q.get(ctx, rekorService, "/api/v1/log/entries?logIndex="+term, &byUUID); err != nil {
			return nil, notFoundIsEmpty(err)
		}
		return decodeAll(byUUID), nil
	case digestPattern.MatchString(term):
		data, err := q.do(ctx, http.MethodPost, q.serviceURL(rekorService, "/api/v1/index/retrieve"),
			map[string]any{"hash": "sha256:" + strings.TrimPrefix(term, "sha256:")})
		if err != nil {
			return nil, notFoundIsEmpty(err)
		}
		var uuids []string
		if err := json.Unmarshal(data, &uuids); err != nil {
			return nil, err
		}
		entries := []Entry{}
		for _, uuid := range uuids {
			if !uuidPattern.MatchString(uuid) {
				continue
			}
			found, err := q.entry(ctx, uuid)
			if err != nil {
				return entries, err
			}
			entries = append(entries, found...)
		}
		sort.Slice(entries, func(a, b int) bool { return entries[a].LogIndex > entries[b].LogIndex })
		// Sixty-four hex characters name a digest or an entry; when nothing
		// was signed with that digest, it is looked up as an entry.
		if len(entries) == 0 && !strings.HasPrefix(term, "sha256:") {
			found, err := q.entry(ctx, term)
			return found, notFoundIsEmpty(err)
		}
		return entries, nil
	case uuidPattern.MatchString(term):
		found, err := q.entry(ctx, term)
		return found, notFoundIsEmpty(err)
	}
	return nil, errors.New("search for a log index, an entry UUID, or a sha256 digest")
}

func (q *querier) entry(ctx context.Context, uuid string) ([]Entry, error) {
	var byUUID map[string]rawEntry
	if err := q.get(ctx, rekorService, "/api/v1/log/entries/"+uuid, &byUUID); err != nil {
		return nil, err
	}
	return decodeAll(byUUID), nil
}

func notFoundIsEmpty(err error) error {
	if errors.Is(err, errNotFound) {
		return nil
	}
	return err
}

// ── Decoding ─────────────────────────────────────────────────────────────────

// rawEntry is a log entry as Rekor returns it.
type rawEntry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof *struct {
			TreeSize int64 `json:"treeSize"`
		} `json:"inclusionProof"`
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

// entryBody is the logged statement. Which fields are set depends on the kind.
type entryBody struct {
	Kind string `json:"kind"`
	Spec struct {
		// hashedrekord
		Data struct {
			Hash hashValue `json:"hash"`
		} `json:"data"`
		Signature struct {
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
		// dsse
		PayloadHash hashValue `json:"payloadHash"`
		Signatures  []struct {
			Verifier string `json:"verifier"`
		} `json:"signatures"`
		// intoto
		Content struct {
			Hash        hashValue `json:"hash"`
			PayloadHash hashValue `json:"payloadHash"`
		} `json:"content"`
		PublicKey string `json:"publicKey"`
	} `json:"spec"`
}

type hashValue struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

func (h hashValue) String() string {
	if h.Value == "" {
		return ""
	}
	algorithm := h.Algorithm
	if algorithm == "" {
		algorithm = "sha256"
	}
	return algorithm + ":" + h.Value
}

func decodeAll(byUUID map[string]rawEntry) []Entry {
	entries := make([]Entry, 0, len(byUUID))
	for uuid, raw := range byUUID {
		entries = append(entries, decodeEntry(uuid, raw))
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].LogIndex > entries[b].LogIndex })
	return entries
}

// decodeEntry reads what an entry says: what was signed, and by whom,
// according to the certificate logged with it. An entry it cannot read is
// still returned, with what the log itself recorded.
func decodeEntry(uuid string, raw rawEntry) Entry {
	entry := Entry{
		LogIndex:        raw.LogIndex,
		UUID:            uuid,
		InclusionProof:  raw.Verification.InclusionProof != nil,
		SignedTimestamp: raw.Verification.SignedEntryTimestamp != "",
	}
	if raw.Verification.InclusionProof != nil {
		entry.ProofTreeSize = raw.Verification.InclusionProof.TreeSize
	}
	if raw.IntegratedTime > 0 {
		at := time.Unix(raw.IntegratedTime, 0).UTC()
		entry.IntegratedTime = &at
	}
	decoded, err := base64.StdEncoding.DecodeString(raw.Body)
	if err != nil {
		return entry
	}
	var body entryBody
	if err := json.Unmarshal(decoded, &body); err != nil {
		return entry
	}
	entry.Kind = body.Kind

	var verifier string
	switch body.Kind {
	case "hashedrekord":
		entry.ArtifactHash = body.Spec.Data.Hash.String()
		verifier = body.Spec.Signature.PublicKey.Content
	case "dsse":
		entry.ArtifactHash = body.Spec.PayloadHash.String()
		if len(body.Spec.Signatures) > 0 {
			verifier = body.Spec.Signatures[0].Verifier
		}
	case "intoto":
		entry.ArtifactHash = body.Spec.Content.PayloadHash.String()
		if entry.ArtifactHash == "" {
			entry.ArtifactHash = body.Spec.Content.Hash.String()
		}
		verifier = body.Spec.PublicKey
	}
	pemBytes, err := base64.StdEncoding.DecodeString(verifier)
	if err != nil {
		return entry
	}
	if certs := parseCertificates(pemBytes); len(certs) > 0 {
		cert := certs[0]
		entry.Subject = certSubject(cert)
		entry.Issuer = certOIDCIssuer(cert)
		entry.CertNotBefore, entry.CertNotAfter = &cert.NotBefore, &cert.NotAfter
		entry.CertSerial = cert.SerialNumber.Text(16)
	}
	return entry
}

func parseCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return certs
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
}

// certSubject is the identity a Fulcio certificate was issued to: a SPIFFE ID
// or another URI, or an email address.
func certSubject(cert *x509.Certificate) string {
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	return cert.Subject.String()
}

// certOIDCIssuer is the identity provider that vouched for the subject.
func certOIDCIssuer(cert *x509.Certificate) string {
	legacy := ""
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidFulcioIssuerV2):
			var issuer string
			if _, err := asn1.Unmarshal(ext.Value, &issuer); err == nil {
				return issuer
			}
		case ext.Id.Equal(oidFulcioIssuer):
			legacy = string(ext.Value)
		}
	}
	return legacy
}

func certInfo(cert *x509.Certificate) CertInfo {
	return CertInfo{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Fingerprint: fingerprint(cert.Raw),
		IsCA:        cert.IsCA,
	}
}

// fingerprint is the SHA-256 of a key or certificate: of the DER bytes when
// it is PEM, so that whitespace and line endings do not change it.
func fingerprint(data []byte) string {
	data = bytes.TrimSpace(data)
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

// handler serves the queries to the page:
//
//	GET /sigstore/summary?namespace=default
//	GET /sigstore/entries?limit=20&before=120
//	GET /sigstore/search?q=<log index | entry UUID | sha256 digest>
func (q *querier) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sigstore/summary", func(w http.ResponseWriter, r *http.Request) {
		namespace := r.URL.Query().Get("namespace")
		if namespace == "" {
			namespace = "default"
		}
		if !nsPattern.MatchString(namespace) {
			writeError(w, http.StatusBadRequest, errors.New("not a namespace name"))
			return
		}
		writeJSON(w, q.Summary(r.Context(), namespace))
	})
	mux.HandleFunc("/sigstore/entries", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
		page, err := q.Entries(r.Context(), before, limit)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, page)
	})
	mux.HandleFunc("/sigstore/search", func(w http.ResponseWriter, r *http.Request) {
		entries, err := q.Search(r.Context(), r.URL.Query().Get("q"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if entries == nil {
			entries = []Entry{}
		}
		writeJSON(w, map[string]any{"entries": entries})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
