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
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	immudb "github.com/blanketops/secure-software-supplychain/pkg/immudb"
	"github.com/blanketops/secure-software-supplychain/pkg/signing"
)

// The SQL tables a build's evidence is stored in. A build, identified by its
// image digest, has one row in builds and one row per record in the table of
// its kind, keyed by (digest, n): n is the record's position in the build's
// evidence. All of a build's rows are written in one transaction.
const (
	TableBuilds     = "builds"
	TableSignatures = "signatures"
	// TableProvenances holds SLSA provenance attestations, TableSBOMs the
	// SBOM attestations, and TableAttestations every other attestation (the
	// build's authorization proofs).
	TableProvenances  = "provenances"
	TableSBOMs        = "sboms"
	TableAttestations = "attestations"
)

// attestationTables are the tables of attestation records; their rows have
// predicate_type as well.
var attestationTables = []string{TableAttestations, TableProvenances, TableSBOMs}

// sbomPredicateTypes are the SBOM formats cosign attests.
var sbomPredicateTypes = []string{signing.SBOMPredicateType, "https://spdx.dev/Document"}

// tableFor is the table a record of kind and predicateType is stored in.
func tableFor(kind, predicateType string) (string, error) {
	switch {
	case kind == KindSignature:
		return TableSignatures, nil
	case kind != KindAttestation:
		return "", fmt.Errorf("unknown kind %q", kind)
	case strings.HasPrefix(predicateType, "https://slsa.dev/provenance/"):
		return TableProvenances, nil
	case slices.Contains(sbomPredicateTypes, predicateType):
		return TableSBOMs, nil
	}
	return TableAttestations, nil
}

// recordColumns are the columns of a signature row; an attestation row has
// predicate_type as well. Each is a field of SignatureRecord.
const recordColumns = `
	digest VARCHAR[128] NOT NULL,
	n INTEGER NOT NULL,
	signed_by VARCHAR[16] NOT NULL,
	subject VARCHAR,
	issuer VARCHAR,
	key_fingerprint VARCHAR,
	certificate_fingerprint VARCHAR,
	certificate VARCHAR,
	not_before TIMESTAMP,
	not_after TIMESTAMP,
	rekor_log_index INTEGER,
	rekor_log_id VARCHAR,
	integrated_at TIMESTAMP,`

var schema = []string{
	`CREATE TABLE IF NOT EXISTS ` + TableBuilds + ` (
	digest VARCHAR[128] NOT NULL,
	image VARCHAR,
	image_build VARCHAR,
	git_commit VARCHAR,
	records INTEGER NOT NULL,
	stored_at TIMESTAMP,
	provenance_log_index INTEGER,
	log_entries INTEGER,
	PRIMARY KEY (digest))`,
	`CREATE TABLE IF NOT EXISTS ` + TableSignatures + ` (` + recordColumns + `
	PRIMARY KEY (digest, n))`,
	`CREATE TABLE IF NOT EXISTS ` + TableRekorEntries + ` (
	digest VARCHAR[128] NOT NULL,
	run VARCHAR[128] NOT NULL,
	rekor_log_index INTEGER NOT NULL,
	rekor_uuid VARCHAR,
	rekor_log_id VARCHAR,
	integrated_at TIMESTAMP,
	PRIMARY KEY (digest, run))`,
}

// TableRekorEntries holds the transparency log entries Tekton Chains made
// when it signed a build's PipelineRun and each of its TaskRuns, keyed by
// (digest, run): most of them are not attached to the image, so they are
// found only here and in the log.
const TableRekorEntries = "rekor_entries"

// column is a column a table made by an earlier version lacks.
type column struct{ name, sqlType string }

// buildsAddedColumns are the columns of builds added after it was first
// made; a builds table that lacks them gets them.
var buildsAddedColumns = []column{{"provenance_log_index", "INTEGER"}, {"log_entries", "INTEGER"}}

// addMissingColumns adds to table the columns it does not have. Rows written
// before read NULL in them.
func addMissingColumns(s immudb.Store, table string, columns []column) error {
	have, err := s.Columns(table)
	if err != nil {
		return err
	}
	for _, c := range columns {
		if slices.Contains(have, c.name) {
			continue
		}
		if _, _, err := s.ExecAll(immudb.Statement{SQL: "ALTER TABLE " + table + " ADD COLUMN " + c.name + " " + c.sqlType}); err != nil {
			return fmt.Errorf("evidence: adding %s to %s: %w", c.name, table, err)
		}
	}
	return nil
}

func init() {
	for _, table := range attestationTables {
		schema = append(schema, `CREATE TABLE IF NOT EXISTS `+table+` (`+recordColumns+`
	predicate_type VARCHAR,
	PRIMARY KEY (digest, n))`)
	}
}

const selectRecord = `digest, n, signed_by, subject, issuer, key_fingerprint, certificate_fingerprint,
	certificate, not_before, not_after, rekor_log_index, rekor_log_id, integrated_at`

// MaxRecordBytes caps the text of one record. immudb accepts far larger
// rows, but a build's rows are read back in one gRPC message of at most
// 4 MiB; a build written over that could never be verified. A real record,
// certificate included, is about 2 KB.
const MaxRecordBytes = 64 << 10

func recordBytes(r supplychainv1alpha1.SignatureRecord) int {
	return len(r.Kind) + len(r.PredicateType) + len(r.SignedBy) + len(r.Subject) + len(r.Issuer) +
		len(r.KeyFingerprint) + len(r.CertificateFingerprint) + len(r.Certificate) + len(r.RekorLogID)
}

// Build is the build whose evidence is stored: its image digest, which
// identifies it, and where it came from.
type Build struct {
	Digest string
	// Image is the image URL the build pushed.
	Image string
	// ImageBuild is the namespace/name of the ImageBuild.
	ImageBuild string
	// Commit is the git commit the image was built from.
	Commit string
}

// StoredBuildEvidence is the evidence of one build as read back from immudb.
type StoredBuildEvidence struct {
	Build   Build
	Records []supplychainv1alpha1.SignatureRecord
	// LogEntries are the transparency log entries of the build's runs, in
	// log order, and ProvenanceLogIndex the PipelineRun's among them.
	LogEntries         []supplychainv1alpha1.RunLogEntry
	ProvenanceLogIndex *int64
	// Tx is the immudb transaction that wrote the build's evidence and Root
	// that transaction's root.
	Tx   uint64
	Root []byte
}

// EnsureSchema creates the evidence tables that do not exist yet, and adds
// to a builds table made by an earlier version the columns it lacks.
func EnsureSchema(s immudb.Store) error {
	stmts := make([]immudb.Statement, len(schema))
	for i, sql := range schema {
		stmts[i] = immudb.Statement{SQL: sql}
	}
	if _, _, err := s.ExecAll(stmts...); err != nil {
		return fmt.Errorf("evidence: creating the evidence tables: %w", err)
	}
	return addMissingColumns(s, TableBuilds, buildsAddedColumns)
}

// PutBuildEvidence writes the build's row, one row per evidence record (its
// signatures and attestations) and one row per transparency log entry of its
// runs to immudb in a single transaction. A build is written once: if its
// evidence is already stored, nothing is written and the error is
// immudb.ErrDuplicate.
func PutBuildEvidence(s immudb.Store, b Build, records []supplychainv1alpha1.SignatureRecord, entries []supplychainv1alpha1.RunLogEntry) (tx uint64, root []byte, err error) {
	if b.Digest == "" {
		return 0, nil, errors.New("evidence: no image digest")
	}
	if len(records) == 0 {
		return 0, nil, fmt.Errorf("evidence: no records for %s", b.Digest)
	}
	var provenanceLogIndex any
	for _, e := range entries {
		if e.Run == PipelineRunEntry {
			provenanceLogIndex = e.RekorLogIndex
		}
	}
	stmts := []immudb.Statement{{
		SQL: `INSERT INTO ` + TableBuilds + ` (digest, image, image_build, git_commit, records, stored_at,
				provenance_log_index, log_entries)
			VALUES (@digest, @image, @image_build, @git_commit, @records, @stored_at,
				@provenance_log_index, @log_entries)`,
		Params: map[string]any{
			"digest": b.Digest, "image": orNull(b.Image), "image_build": orNull(b.ImageBuild),
			"git_commit": orNull(b.Commit), "records": len(records), "stored_at": time.Now().UTC(),
			"provenance_log_index": provenanceLogIndex, "log_entries": len(entries),
		},
	}}
	for n, r := range records {
		stmt, err := insertRecord(b.Digest, n, r)
		if err != nil {
			return 0, nil, err
		}
		stmts = append(stmts, stmt)
	}
	for _, e := range entries {
		stmts = append(stmts, immudb.Statement{
			SQL: `INSERT INTO ` + TableRekorEntries + ` (digest, run, rekor_log_index, rekor_uuid, rekor_log_id, integrated_at)
				VALUES (@digest, @run, @rekor_log_index, @rekor_uuid, @rekor_log_id, @integrated_at)`,
			Params: map[string]any{
				"digest": b.Digest, "run": e.Run, "rekor_log_index": e.RekorLogIndex,
				"rekor_uuid": orNull(e.RekorUUID), "rekor_log_id": orNull(e.RekorLogID),
				"integrated_at": timeOrNull(e.IntegratedAt),
			},
		})
	}
	if err := EnsureSchema(s); err != nil {
		return 0, nil, err
	}
	return s.ExecAll(stmts...)
}

func insertRecord(digest string, n int, r supplychainv1alpha1.SignatureRecord) (immudb.Statement, error) {
	if size := recordBytes(r); size > MaxRecordBytes {
		return immudb.Statement{}, fmt.Errorf("evidence: record %d of %s is %d bytes; at most %d are stored", n, digest, size, MaxRecordBytes)
	}
	params := map[string]any{
		"digest": digest, "n": n, "signed_by": r.SignedBy,
		"subject": orNull(r.Subject), "issuer": orNull(r.Issuer),
		"key_fingerprint": orNull(r.KeyFingerprint), "certificate_fingerprint": orNull(r.CertificateFingerprint),
		"certificate": orNull(r.Certificate),
		"not_before":  timeOrNull(r.NotBefore), "not_after": timeOrNull(r.NotAfter),
		"rekor_log_index": nil, "rekor_log_id": orNull(r.RekorLogID),
		"integrated_at": timeOrNull(r.IntegratedAt),
	}
	if r.RekorLogIndex != nil {
		params["rekor_log_index"] = *r.RekorLogIndex
	}
	columns := strings.Fields(strings.ReplaceAll(selectRecord, ",", " "))
	table, err := tableFor(r.Kind, r.PredicateType)
	if err != nil {
		return immudb.Statement{}, fmt.Errorf("evidence: record %d of %s: %w", n, digest, err)
	}
	if table != TableSignatures {
		params["predicate_type"] = orNull(r.PredicateType)
		columns = append(columns, "predicate_type")
	}
	return immudb.Statement{
		SQL: `INSERT INTO ` + table + ` (` + strings.Join(columns, ", ") + `)
			VALUES (@` + strings.Join(columns, ", @") + `)`,
		Params: params,
	}, nil
}

// ReadBuildEvidence reads the evidence of the build of digest back from
// immudb. Every row is verified against the client's trusted state, and
// every record row must have been written in the same transaction as the
// build's row; otherwise the error says which does not. It does not touch
// the registry.
func ReadBuildEvidence(s immudb.Store, digest string) (*StoredBuildEvidence, error) {
	if err := EnsureSchema(s); err != nil {
		return nil, err
	}
	params := map[string]any{"digest": digest}
	builds, err := s.QueryVerified(TableBuilds, []string{"digest"},
		`SELECT digest, image, image_build, git_commit, records, provenance_log_index, log_entries FROM `+TableBuilds+` WHERE digest = @digest`, params)
	if err != nil {
		return nil, fmt.Errorf("evidence: reading the build %s: %w", digest, err)
	}
	if len(builds) == 0 {
		return nil, fmt.Errorf("%w: evidence of %s", immudb.ErrNotFound, digest)
	}
	row := builds[0]
	out := &StoredBuildEvidence{
		Build: Build{
			Digest: digest, Image: str(row.Values["image"]),
			ImageBuild: str(row.Values["image_build"]), Commit: str(row.Values["git_commit"]),
		},
		Tx: row.Tx,
	}
	if out.Root, err = s.Root(row.Tx); err != nil {
		return nil, fmt.Errorf("evidence: root of the build's tx %d: %w", row.Tx, err)
	}
	want, _ := row.Values["records"].(int64)

	byPosition := map[int64]supplychainv1alpha1.SignatureRecord{}
	for _, table := range append([]string{TableSignatures}, attestationTables...) {
		kind, columns := KindAttestation, selectRecord+", predicate_type"
		if table == TableSignatures {
			kind, columns = KindSignature, selectRecord
		}
		rows, err := s.QueryVerified(table, []string{"digest", "n"},
			`SELECT `+columns+` FROM `+table+` WHERE digest = @digest`, params)
		if err != nil {
			return nil, fmt.Errorf("evidence: reading the %s of %s: %w", table, digest, err)
		}
		for _, r := range rows {
			n, _ := r.Values["n"].(int64)
			if r.Tx != out.Tx {
				return nil, fmt.Errorf("evidence: %s row %d of %s was written in tx %d, not in the build's tx %d", table, n, digest, r.Tx, out.Tx)
			}
			if _, dup := byPosition[n]; dup {
				return nil, fmt.Errorf("evidence: record %d of %s is stored in two tables, the second %s", n, digest, table)
			}
			byPosition[n] = recordFromRow(kind, r.Values)
		}
	}
	if int64(len(byPosition)) != want {
		return nil, fmt.Errorf("evidence: the build %s has %d records; its tables hold %d", digest, want, len(byPosition))
	}
	positions := make([]int64, 0, len(byPosition))
	for n := range byPosition {
		positions = append(positions, n)
	}
	sort.Slice(positions, func(i, j int) bool { return positions[i] < positions[j] })
	for i, n := range positions {
		if n != int64(i) {
			return nil, fmt.Errorf("evidence: the build %s has no record %d", digest, i)
		}
		out.Records = append(out.Records, byPosition[n])
	}

	if i, ok := row.Values["provenance_log_index"].(int64); ok {
		out.ProvenanceLogIndex = &i
	}
	// NULL in a row written before log entries were stored: there are none.
	wantEntries, _ := row.Values["log_entries"].(int64)
	entries, err := s.QueryVerified(TableRekorEntries, []string{"digest", "run"},
		`SELECT digest, run, rekor_log_index, rekor_uuid, rekor_log_id, integrated_at FROM `+TableRekorEntries+
			` WHERE digest = @digest`, params)
	if err != nil {
		return nil, fmt.Errorf("evidence: reading the %s of %s: %w", TableRekorEntries, digest, err)
	}
	for _, r := range entries {
		if r.Tx != out.Tx {
			return nil, fmt.Errorf("evidence: %s row %s of %s was written in tx %d, not in the build's tx %d",
				TableRekorEntries, str(r.Values["run"]), digest, r.Tx, out.Tx)
		}
		index, _ := r.Values["rekor_log_index"].(int64)
		out.LogEntries = append(out.LogEntries, supplychainv1alpha1.RunLogEntry{
			Run: str(r.Values["run"]), RekorLogIndex: index, RekorUUID: str(r.Values["rekor_uuid"]),
			RekorLogID: str(r.Values["rekor_log_id"]), IntegratedAt: metaTime(r.Values["integrated_at"]),
		})
	}
	if int64(len(out.LogEntries)) != wantEntries {
		return nil, fmt.Errorf("evidence: the build %s has %d log entries; its table holds %d", digest, wantEntries, len(out.LogEntries))
	}
	sort.Slice(out.LogEntries, func(i, j int) bool { return out.LogEntries[i].RekorLogIndex < out.LogEntries[j].RekorLogIndex })
	return out, nil
}

func recordFromRow(kind string, v map[string]any) supplychainv1alpha1.SignatureRecord {
	r := supplychainv1alpha1.SignatureRecord{
		Kind:                   kind,
		PredicateType:          str(v["predicate_type"]),
		SignedBy:               str(v["signed_by"]),
		Subject:                str(v["subject"]),
		Issuer:                 str(v["issuer"]),
		KeyFingerprint:         str(v["key_fingerprint"]),
		CertificateFingerprint: str(v["certificate_fingerprint"]),
		Certificate:            str(v["certificate"]),
		NotBefore:              metaTime(v["not_before"]),
		NotAfter:               metaTime(v["not_after"]),
		RekorLogID:             str(v["rekor_log_id"]),
		IntegratedAt:           metaTime(v["integrated_at"]),
	}
	if i, ok := v["rekor_log_index"].(int64); ok {
		r.RekorLogIndex = &i
	}
	return r
}

// orNull stores an empty string as NULL.
func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func timeOrNull(t *metav1.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func metaTime(v any) *metav1.Time {
	t, ok := v.(time.Time)
	if !ok {
		return nil
	}
	mt := metav1.NewTime(t)
	return &mt
}
