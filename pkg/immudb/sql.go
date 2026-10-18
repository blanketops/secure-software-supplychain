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

package immudb

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/codenotary/immudb/embedded/store"
	"github.com/codenotary/immudb/pkg/api/schema"
	"google.golang.org/grpc/status"
)

// Statement is one SQL statement and its named parameters, written @name in
// the SQL.
type Statement struct {
	SQL    string
	Params map[string]any
}

// Row is one row read by QueryVerified: its values by column name (NULL is
// nil, INTEGER int64, TIMESTAMP time.Time) and the transaction that wrote it.
type Row struct {
	Values map[string]any
	Tx     uint64
}

// ExecAll runs the statements in one SQL transaction: all of them are
// committed, or none. A statement that inserts an existing primary key
// rejects the transaction with ErrDuplicate. When the statements change
// nothing, no transaction is committed and tx is 0.
func (s *immudbStore) ExecAll(stmts ...Statement) (uint64, []byte, error) {
	if len(stmts) == 0 {
		return 0, nil, errors.New("immudb: no statements to execute")
	}
	ctx := context.Background()
	tx, err := s.c.NewTx(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("immudb: begin transaction: %w", err)
	}
	for i, st := range stmts {
		if err := tx.SQLExec(ctx, st.SQL, st.Params); err != nil {
			_ = tx.Rollback(ctx)
			if isKeyAlreadyExists(err) {
				return 0, nil, fmt.Errorf("%w: statement %d of %d: %s", ErrDuplicate, i+1, len(stmts), firstLine(st.SQL))
			}
			return 0, nil, fmt.Errorf("immudb: statement %d of %d (%s): %w", i+1, len(stmts), firstLine(st.SQL), err)
		}
	}
	committed, err := tx.Commit(ctx)
	if err != nil {
		if isKeyAlreadyExists(err) {
			return 0, nil, fmt.Errorf("%w: commit of %d statements", ErrDuplicate, len(stmts))
		}
		return 0, nil, fmt.Errorf("immudb: commit: %w", err)
	}
	id := committed.GetHeader().GetId()
	if id == 0 {
		// Nothing changed (CREATE TABLE IF NOT EXISTS of a table that
		// exists): the server commits no transaction.
		return 0, nil, nil
	}
	root, err := s.root(ctx, id)
	if err != nil {
		return 0, nil, err
	}
	return id, root, nil
}

// QueryVerified runs a SELECT on table and verifies every row it returns
// against the client's trusted state, so a row the server altered is an
// error, not a result. pk names the table's primary key columns; the query
// must select them.
func (s *immudbStore) QueryVerified(table string, pk []string, sql string, params map[string]any) ([]Row, error) {
	if len(pk) == 0 {
		return nil, errors.New("immudb: QueryVerified needs the primary key columns")
	}
	ctx := context.Background()
	res, err := s.c.SQLQuery(ctx, sql, params, false)
	if err != nil {
		return nil, fmt.Errorf("immudb: query %s: %w", table, err)
	}
	position := make(map[string]int, len(res.Columns))
	for i, col := range res.Columns {
		position[columnName(col.Name)] = i
	}
	for _, name := range pk {
		if _, ok := position[name]; !ok {
			return nil, fmt.Errorf("immudb: query of %s does not select primary key column %s, so its rows cannot be verified", table, name)
		}
	}

	rows := make([]Row, 0, len(res.Rows))
	for _, r := range res.Rows {
		pkVals := make([]*schema.SQLValue, len(pk))
		for i, name := range pk {
			pkVals[i] = r.Values[position[name]]
		}
		if err := s.c.VerifyRow(ctx, &schema.Row{Columns: r.Columns, Values: r.Values}, table, pkVals); err != nil {
			return nil, fmt.Errorf("immudb: row %v of %s does not verify: %w", rawValues(pkVals), table, err)
		}
		// VerifyRow proves the row but does not say which transaction wrote
		// it; the same verifiable read carries that.
		entry, err := s.c.GetServiceClient().VerifiableSQLGet(ctx, &schema.VerifiableSQLGetRequest{
			SqlGetRequest: &schema.SQLGetRequest{Table: table, PkValues: pkVals},
		})
		if err != nil {
			return nil, fmt.Errorf("immudb: transaction of row %v of %s: %w", rawValues(pkVals), table, err)
		}
		values := make(map[string]any, len(r.Columns))
		for i, col := range r.Columns {
			values[columnName(col)] = schema.RawValue(r.Values[i])
		}
		rows = append(rows, Row{Values: values, Tx: entry.GetSqlEntry().GetTx()})
	}
	return rows, nil
}

// Columns returns the columns of table, in order. It reads the catalog, which
// has no proofs; it tells what a table looks like, not what it holds.
func (s *immudbStore) Columns(table string) ([]string, error) {
	if !isIdentifier(table) {
		return nil, fmt.Errorf("immudb: %q is not a table name", table)
	}
	res, err := s.c.SQLQuery(context.Background(), "SELECT name FROM COLUMNS('"+table+"')", nil, false)
	if err != nil {
		return nil, fmt.Errorf("immudb: columns of %s: %w", table, err)
	}
	names := make([]string, 0, len(res.Rows))
	for _, r := range res.Rows {
		names = append(names, r.Values[0].GetS())
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("immudb: table %s has no columns", table)
	}
	return names, nil
}

// columnName reduces the server's "(table.column)" to "column".
func columnName(selector string) string {
	name := strings.TrimSuffix(strings.TrimPrefix(selector, "("), ")")
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return name
}

func rawValues(vals []*schema.SQLValue) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		out[i] = schema.RawValue(v)
	}
	return out
}

// isKeyAlreadyExists reports whether err is the server rejecting an insert
// of an existing primary key. Like "key not found", it arrives as gRPC
// Unknown, so only the message identifies it.
func isKeyAlreadyExists(err error) bool {
	st, ok := status.FromError(err)
	msg := err.Error()
	if ok {
		msg = st.Message()
	}
	return strings.HasSuffix(msg, store.ErrKeyAlreadyExists.Error())
}

func firstLine(sql string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(sql), "\n")
	return line
}
