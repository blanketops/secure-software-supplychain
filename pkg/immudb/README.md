# immudb store

`pkg/immudb` is the client of the immudb database that holds the supply chain's evidence. Every write and read goes
to the server and is verified against the client's trusted state; there is no in-memory fallback. `Open()` returns
an error when the server cannot be reached or rejects the login.

## Connection

`Open()` reads `IMMUDB_ADDR`, `IMMUDB_PORT`, `IMMUDB_USER`, `IMMUDB_PASSWORD` and `IMMUDB_DB` (defaults
`127.0.0.1`, `3322`, `immudb`, `immudb`, `securesoftwaresupplychain`). The client keeps its trusted state in
`IMMUDB_STATE_DIR` (default: `immudb` under the user's cache directory).

## Store

| Method | What it does |
|---|---|
| `ExecAll(stmts...)` | Runs SQL statements in one transaction: all are committed or none. Inserting an existing primary key is `ErrDuplicate`. Statements that change nothing commit no transaction and return tx 0 |
| `QueryVerified(table, pk, sql, params)` | Runs a `SELECT` on one table and verifies every returned row (`VerifyRow`); each `Row` carries its values by column name and the transaction that wrote it. The query must select the primary key columns `pk` |
| `Root(tx)` | The accumulated hash (Alh) of transaction `tx`, verified |
| `CreateDatabase(name)` | Creates a database if it does not exist, on the server the `IMMUDB_*` variables name |
| `Put`, `PutAll`, `Get`, `Verify` | Key-value writes and verified reads; `PutAll` writes every key in one transaction, each under `KeyMustNotExist` |

The evidence itself (tables `builds`, `signatures`, `provenances`, `sboms`, `attestations`) is defined in `pkg/evidence/immudb.go`, and
described in [installation](../../docs/installation.md#where-the-evidence-is-stored-immudb).

## Tests

The tests run against a real immudb and fail without one. They use the database `securesoftwaresupplychain_test`
(`IMMUDB_TEST_DB`, created on first use), never the pipeline's; a name that does not end in `_test` is refused.
Tests in other packages get it from `pkg/immudb/immudbtest` (`Use`, `Open`):

```sh
go test ./pkg/immudb/... -v
```

SQL tests write to the table `store_sql_test`; key-value tests to keys named after the test. immudb keeps every
write, so each run uses new keys.
