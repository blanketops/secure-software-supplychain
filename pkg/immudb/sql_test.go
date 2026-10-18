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
	"errors"
	"testing"
	"time"
)

// sqlTestTable is the one table these tests write to. immudb keeps every
// write, so each test uses its own key (uniqueKey) instead of its own table.
const sqlTestTable = "store_sql_test"

func sqlTestStore(t *testing.T) Store {
	t.Helper()
	s := openTestStore(t)
	if _, _, err := s.ExecAll(Statement{SQL: `CREATE TABLE IF NOT EXISTS ` + sqlTestTable + ` (
		id VARCHAR[256], n INTEGER, s VARCHAR, at TIMESTAMP, ok BOOLEAN,
		PRIMARY KEY (id, n))`}); err != nil {
		t.Fatalf("creating %s: %v", sqlTestTable, err)
	}
	return s
}

func insertRow(id string, n int, s any) Statement {
	return Statement{
		SQL:    `INSERT INTO ` + sqlTestTable + ` (id, n, s, at, ok) VALUES (@id, @n, @s, @at, @ok)`,
		Params: map[string]any{"id": id, "n": n, "s": s, "at": time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC), "ok": n == 0},
	}
}

func queryRows(t *testing.T, s Store, id string) []Row {
	t.Helper()
	rows, err := s.QueryVerified(sqlTestTable, []string{"id", "n"},
		`SELECT id, n, s, at, ok FROM `+sqlTestTable+` WHERE id = @id ORDER BY n`, map[string]any{"id": id})
	if err != nil {
		t.Fatalf("QueryVerified: %v", err)
	}
	return rows
}

// TestExecAllIsOneTransaction: the statements of one ExecAll land in one
// transaction, and every row read back carries it.
func TestExecAllIsOneTransaction(t *testing.T) {
	s := sqlTestStore(t)
	id := uniqueKey(t, "row")
	tx, root, err := s.ExecAll(insertRow(id, 0, "first"), insertRow(id, 1, nil))
	if err != nil {
		t.Fatalf("ExecAll: %v", err)
	}
	if tx == 0 || len(root) == 0 {
		t.Fatalf("ExecAll = tx %d, root %x; want a transaction and its root", tx, root)
	}

	rows := queryRows(t, s, id)
	if len(rows) != 2 {
		t.Fatalf("read %d rows; want 2", len(rows))
	}
	for _, r := range rows {
		if r.Tx != tx {
			t.Errorf("row %v written in tx %d; want %d", r.Values["n"], r.Tx, tx)
		}
	}
	first := rows[0].Values
	if first["id"] != id || first["n"] != int64(0) || first["s"] != "first" || first["ok"] != true ||
		!first["at"].(time.Time).Equal(time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("first row = %v; want the values written", first)
	}
	if rows[1].Values["s"] != nil {
		t.Errorf("second row s = %v; want NULL as nil", rows[1].Values["s"])
	}
}

// TestExecAllDuplicateWritesNothing: a statement that hits an existing
// primary key rejects the whole transaction.
func TestExecAllDuplicateWritesNothing(t *testing.T) {
	s := sqlTestStore(t)
	id := uniqueKey(t, "row")
	if _, _, err := s.ExecAll(insertRow(id, 0, "first")); err != nil {
		t.Fatalf("ExecAll: %v", err)
	}
	_, _, err := s.ExecAll(insertRow(id, 1, "new"), insertRow(id, 0, "again"))
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("ExecAll over an existing primary key = %v; want ErrDuplicate", err)
	}
	if rows := queryRows(t, s, id); len(rows) != 1 || rows[0].Values["s"] != "first" {
		t.Fatalf("after the rejected transaction: %v; want only the first row", rows)
	}
}

// TestRootOfTransaction: Root returns the root ExecAll reported for its
// transaction.
func TestRootOfTransaction(t *testing.T) {
	s := sqlTestStore(t)
	tx, root, err := s.ExecAll(insertRow(uniqueKey(t, "row"), 0, "first"))
	if err != nil {
		t.Fatalf("ExecAll: %v", err)
	}
	got, err := s.Root(tx)
	if err != nil || string(got) != string(root) {
		t.Fatalf("Root(%d) = %x, %v; want %x", tx, got, err, root)
	}
}

func TestQueryVerifiedNoRows(t *testing.T) {
	if rows := queryRows(t, sqlTestStore(t), uniqueKey(t, "absent")); len(rows) != 0 {
		t.Fatalf("read %v; want no rows", rows)
	}
}

func TestQueryVerifiedNeedsThePrimaryKey(t *testing.T) {
	s := sqlTestStore(t)
	id := uniqueKey(t, "row")
	if _, _, err := s.ExecAll(insertRow(id, 0, "first")); err != nil {
		t.Fatalf("ExecAll: %v", err)
	}
	if _, err := s.QueryVerified(sqlTestTable, []string{"id", "n"},
		`SELECT s FROM `+sqlTestTable+` WHERE id = @id`, map[string]any{"id": id}); err == nil {
		t.Fatal("QueryVerified without the primary key columns = nil error; a row cannot be verified without them")
	}
}

func TestExecAllRejectsEmpty(t *testing.T) {
	if _, _, err := openTestStore(t).ExecAll(); err == nil {
		t.Fatal("ExecAll with no statements = nil error")
	}
}

// TestExecAllThatChangesNothing: re-creating an existing table commits no
// transaction; that is not an error.
func TestExecAllThatChangesNothing(t *testing.T) {
	s := sqlTestStore(t)
	tx, root, err := s.ExecAll(Statement{SQL: `CREATE TABLE IF NOT EXISTS ` + sqlTestTable + ` (
		id VARCHAR[256], n INTEGER, s VARCHAR, at TIMESTAMP, ok BOOLEAN, PRIMARY KEY (id, n))`})
	if err != nil || tx != 0 || root != nil {
		t.Fatalf("ExecAll that changes nothing = tx %d, root %x, %v; want tx 0, no root, no error", tx, root, err)
	}
}
