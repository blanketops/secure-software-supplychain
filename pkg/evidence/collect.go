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

// Package evidence reads back what vouches for a built image: the signatures
// and attestations stored next to it in the registry, and the transparency
// log entry of each.
package evidence

import (
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
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

const (
	KindSignature   = "Signature"
	KindAttestation = "Attestation"

	SignedByBuild  = "Build"
	SignedByChains = "Chains"
	SignedByOther  = "Other"

	// Annotations cosign and Tekton Chains put on each signature layer.
	annotationSignature   = "dev.cosignproject.cosign/signature"
	annotationCertificate = "dev.sigstore.cosign/certificate"
	annotationBundle      = "dev.sigstore.cosign/bundle"
	annotationPredicate   = "predicateType"

	// maxBlobSize bounds what is read for one attestation.
	maxBlobSize = 8 << 20
)

// Fulcio records the OIDC issuer in these certificate extensions: the first
// as a raw string, the second, which replaces it, as a DER UTF8String.
var (
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// Options says which image to read the evidence of, and how.
type Options struct {
	// Image is the image reference that was pushed; its tag is ignored.
	Image string
	// Digest is the digest of the image manifest, "sha256:...".
	Digest string
	// RekorURL is the transparency log the entries are looked up in.
	RekorURL string
	// BuildSubject and ChainsSubject are the certificate identities of the
	// SupplyChain's ServiceAccount and of Tekton Chains.
	BuildSubject  string
	ChainsSubject string
	// Keychain holds the registry credentials. Nil reads anonymously.
	Keychain authn.Keychain
	// HTTPClient talks to Rekor. Nil uses a client with a short timeout.
	HTTPClient *http.Client
	// NameOptions and RemoteOptions adjust registry access, for tests.
	NameOptions   []name.Option
	RemoteOptions []remote.Option
}

// Collect lists every signature and attestation on the image, each with its
// signer, key and transparency log entry, ordered as the log recorded them.
//
// A record whose log entry cannot be found is still returned, without an
// index, and the error says so: the registry content is the fact, the log
// entry is what was being looked for.
func Collect(ctx context.Context, opts Options) ([]supplyv1alpha1.SignatureRecord, error) {
	ref, err := name.ParseReference(opts.Image, opts.NameOptions...)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", opts.Image, err)
	}
	repo := ref.Context()
	remoteOpts := append([]remote.Option{remote.WithContext(ctx)}, opts.RemoteOptions...)
	if opts.Keychain != nil {
		remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(opts.Keychain))
	}
	log := &rekor{base: strings.TrimRight(opts.RekorURL, "/"), http: opts.HTTPClient}
	if log.http == nil {
		log.http = &http.Client{Timeout: 15 * time.Second}
	}

	var (
		records []supplyv1alpha1.SignatureRecord
		errs    []error
	)
	for kind, suffix := range map[string]string{KindSignature: "sig", KindAttestation: "att"} {
		tag := repo.Tag(strings.Replace(opts.Digest, ":", "-", 1) + "." + suffix)
		desc, err := remote.Get(tag, remoteOpts...)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("reading %s: %w", tag, err))
			continue
		}
		image, err := desc.Image()
		if err != nil {
			errs = append(errs, fmt.Errorf("reading %s: %w", tag, err))
			continue
		}
		manifest, err := image.Manifest()
		if err != nil {
			errs = append(errs, fmt.Errorf("reading %s: %w", tag, err))
			continue
		}
		for _, layer := range manifest.Layers {
			record, err := describe(ctx, kind, image, layer, log, opts)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s %s: %w", strings.ToLower(kind), layer.Digest, err))
			}
			if record != nil {
				records = append(records, *record)
			}
		}
	}

	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i].RekorLogIndex, records[j].RekorLogIndex
		switch {
		case a == nil || b == nil:
			return a != nil
		case *a != *b:
			return *a < *b
		}
		return records[i].Kind > records[j].Kind
	})
	return records, errors.Join(errs...)
}

// describe turns one layer of a signature or attestation image into a record.
func describe(
	ctx context.Context,
	kind string,
	image v1.Image,
	layer v1.Descriptor,
	log *rekor,
	opts Options,
) (*supplyv1alpha1.SignatureRecord, error) {
	record := &supplyv1alpha1.SignatureRecord{Kind: kind, SignedBy: SignedByOther}
	if err := describeSigner(record, layer.Annotations[annotationCertificate], opts); err != nil {
		return record, err
	}

	// What the log indexed the entry under, and how to tell it from other
	// entries with the same index key.
	var (
		hash  string
		match func(entryBody) bool
	)
	if kind == KindSignature {
		// The layer is the signed payload itself.
		signature := layer.Annotations[annotationSignature]
		hash = layer.Digest.String()
		match = func(body entryBody) bool {
			return body.Kind == "hashedrekord" && body.Spec.Signature.Content == signature
		}
	} else {
		payload, predicateType, err := attestationPayload(image, layer)
		if err != nil {
			return record, err
		}
		record.PredicateType = predicateType
		if record.PredicateType == "" {
			record.PredicateType = layer.Annotations[annotationPredicate]
		}
		sum := sha256.Sum256(payload)
		payloadHash := hex.EncodeToString(sum[:])
		hash = "sha256:" + payloadHash
		match = func(body entryBody) bool {
			return body.Spec.PayloadHash.Value == payloadHash || body.Spec.Content.PayloadHash.Value == payloadHash
		}
	}

	// cosign stores the log's answer with the signature; Chains does not.
	if bundle := layer.Annotations[annotationBundle]; bundle != "" {
		var parsed struct {
			Payload struct {
				IntegratedTime int64  `json:"integratedTime"`
				LogIndex       int64  `json:"logIndex"`
				LogID          string `json:"logID"`
			}
		}
		if err := json.Unmarshal([]byte(bundle), &parsed); err == nil && parsed.Payload.LogID != "" {
			setLogEntry(record, parsed.Payload.LogIndex, parsed.Payload.LogID, parsed.Payload.IntegratedTime)
			return record, nil
		}
	}

	entries, err := log.find(ctx, hash)
	if err != nil {
		return record, fmt.Errorf("looking up the transparency log entry: %w", err)
	}
	for _, entry := range entries {
		if match(entry.Body) {
			setLogEntry(record, entry.LogIndex, entry.LogID, entry.IntegratedTime)
			return record, nil
		}
	}
	return record, errors.New("no transparency log entry found")
}

func setLogEntry(record *supplyv1alpha1.SignatureRecord, index int64, logID string, integratedTime int64) {
	record.RekorLogIndex = &index
	record.RekorLogID = logID
	if integratedTime > 0 {
		t := metav1.NewTime(time.Unix(integratedTime, 0).UTC())
		record.IntegratedAt = &t
	}
}

// describeSigner fills in who signed, from the Fulcio certificate.
func describeSigner(record *supplyv1alpha1.SignatureRecord, certPEM string, opts Options) error {
	if certPEM == "" {
		return errors.New("no signing certificate; signed with a long-lived key")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("signing certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing the signing certificate: %w", err)
	}

	switch {
	case len(cert.URIs) > 0:
		record.Subject = cert.URIs[0].String()
	case len(cert.EmailAddresses) > 0:
		record.Subject = cert.EmailAddresses[0]
	}
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidIssuerV2):
			var issuer string
			if _, err := asn1.Unmarshal(ext.Value, &issuer); err == nil {
				record.Issuer = issuer
			}
		case ext.Id.Equal(oidIssuerV1) && record.Issuer == "":
			record.Issuer = string(ext.Value)
		}
	}
	switch record.Subject {
	case "":
	case opts.BuildSubject:
		record.SignedBy = SignedByBuild
	case opts.ChainsSubject:
		record.SignedBy = SignedByChains
	}

	record.CertificateFingerprint = fingerprint(cert.Raw)
	record.KeyFingerprint = fingerprint(cert.RawSubjectPublicKeyInfo)
	notBefore, notAfter := metav1.NewTime(cert.NotBefore.UTC()), metav1.NewTime(cert.NotAfter.UTC())
	record.NotBefore, record.NotAfter = &notBefore, &notAfter
	return nil
}

// attestationPayload reads a DSSE envelope and returns the statement it
// carries and that statement's predicate type.
func attestationPayload(image v1.Image, descriptor v1.Descriptor) ([]byte, string, error) {
	layer, err := image.LayerByDigest(descriptor.Digest)
	if err != nil {
		return nil, "", fmt.Errorf("reading the attestation: %w", err)
	}
	blob, err := layer.Compressed()
	if err != nil {
		return nil, "", fmt.Errorf("reading the attestation: %w", err)
	}
	defer func() { _ = blob.Close() }()
	data, err := io.ReadAll(io.LimitReader(blob, maxBlobSize))
	if err != nil {
		return nil, "", fmt.Errorf("reading the attestation: %w", err)
	}

	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, "", fmt.Errorf("attestation is not a DSSE envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("attestation payload is not base64: %w", err)
	}
	var statement struct {
		PredicateType string `json:"predicateType"`
	}
	// The payload is hashed whatever it is; only an in-toto statement names
	// a predicate type.
	_ = json.Unmarshal(payload, &statement)
	return payload, statement.PredicateType, nil
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isNotFound(err error) bool {
	var terr *transport.Error
	return errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound
}
