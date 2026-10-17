# immudb — verifiable store

A small, dependency-free spike of immudb's load-bearing primitive: an
**append-only, cryptographically verifiable log**. Each record appends at the
next index and returns a root hash; after the read, `Verify()` decides whether a
(value, index, root) triple is still authentic. Any later change to a stored
value (or to the root it chains from) fails verification.

This is the part of immudb that matters for the proposed change (move
signatures, attestations, and provenances out of the registry/log into one
verifiable store). It is **not** the full immudb binary-tree implementation; the
actual server uses a Merkle tree over append-only blocks, and that go module
cannot be resolved from this machine's network, so a real client is intentionally
not wired in yet.

## Files

| File | Purpose |
|---|---|
| `pkg/immudb/store.go` | `Store` interface, `memStore`, hash-chain root, `Verify` |
| `pkg/immudb/store_test.go` | Deterministic tests (round-trip, tamper, duplicate, per-index proof) |

## Usage

Records are keyed by `<Kind>:<Digest>` (for example `sig:sha256:abc123` or
`att:sha256:...`). The value is the caller's serialized evidence record (JSON),
so `pkg/evidence` / `pkg/signing` stays the authority and immudb only stores the
record + proof.

```go
s := immudb.Open() // a memStore; swap the body for a real immudb client later

idx, root, err := s.Put("sig:sha256:abc", encodedRecord) // appends, returns root
if err != nil { /* ErrDuplicate if the same key was already stored */ }

v, i, r, err := s.Get("sig:sha256:abc") // value, index, current root

ok, err := s.Verify(root, i, encodedRecord) // false if the store was tampered
```

## Tests

```sh
go test ./pkg/immudb/... -v
```

Covers round-trip verification, value tampering, duplicate keys, missing keys,
sequential indexes, per-index proof independence across appends, and leaf
injectivity. All pass.

## Known limitation

The real immudb Go client/proxy requires a module that this environment cannot
resolve (no working go proxy / TLS to the proxy). Wiring `pkg/evidence` and
`pkg/signing` to write and read `SignatureRecord` via immudb is the remaining
step; the tamper-evidence semantics are already proven by the tests above, and
they are the load-bearing property for "out of the registry, into immudb".
