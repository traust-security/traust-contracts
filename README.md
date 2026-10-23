# Traust Contracts

Source of truth for JSON schemas and enums shared across the Traust ecosystem,
plus generated Python bindings, **the configuration contract** (the one place
that knows what config exists and how it loads), and **storage/v1** (the SQL-first
relational contract and reference write protocol).

## Configuration contract

Contracts owns the configuration *mechanism* for the whole stack — mechanism
only, never estate data:

- **MANIFEST** — the authoritative list of config files (name, required/optional,
  schema, typed model). The single source of truth for “what config exists.”
- **Schemas** — `config/v1/*.schema.json`, applied at load time (versioned
  separately from the `schemas/v1` data schemas).
- **Typed sections + `HarnessContext`** — each file parses into a typed model;
  `HarnessContext` is the frozen bundle of them all.
- **The loader** — `load_context()` (resolve the whole context at an entry point)
  and `load_section()` (one file, for narrow feature-gated readers). Resolution is
  `$TRAUST_CONFIG_HOME`, else the documented default `~/.traust/config` — no env
  overrides, no cwd scanning, no second root.

Consumers declare the subset they need and receive an injected `HarnessContext`
(`traust_engine` never loads config itself); the app (`traust`) is the config
*source* (templates + `install_traust`) and resolves the context once per entry
point. One loader → no two callers disagree about “what the config is.”
Optional `storage.yaml` (e.g. `dsn: postgresql://localhost/traust`) loads as
`context.storage`; `load_section("storage")` provides narrow access. Callers open
connections; `Store` receives them and never resolves configuration.
Optional `ledger.yaml` loads as `context.ledger`: `dsn` (SQLAlchemy URL, usually the
storage database under the ledger's own role) makes the Ledger database the
authority for disposition layers, with layer files as read-only snapshots; without
`dsn`, layer files are the ledger. `signing` (method, key path, keyless options,
`required`) and `identity` (token issuer/audience/JWKS, directory command) apply in
both modes. Secrets (keypair password, tokens) never go in the file.
End-to-end architecture: `traust/docs/architecture.md` → *Configuration & context*.

## Install

```bash
uv add "traust-contracts @ git+https://github.com/traust-security/traust-contracts.git"
```

Go SDK: see [traust-sdk](https://github.com/traust-security/traust-sdk).

## Versioning

Two independent axes:

- **Data-contract version** (`v1`, `v2`, ...) — the shape of schemas/enums
  and everything generated from them. Lives as a real directory; `v2` sits
  beside `v1` once it exists.
- **Package release version** (`VERSION`) — normal semver for this repo.

`traust_contracts.models` / `.enums` / `.paths` alias the current major
(`v1` today). Pin to `traust_contracts.v1.*` directly if the shape must
never move under you.

`adapter-result` contains scanner observations, not authored audit findings.
Its own finding definition allows unreported CWEs/description/remediation while
retaining shared value constraints and opaque native IDs. Unknown observations
are not invented conclusions. The authored report schema remains unchanged.

## Storage contract

New here? Start with the diagrams in [docs/data-model.md](docs/data-model.md):
the product → repo registry, artifacts, projections and the ledger, and how they join.

`storage/v1` ships readable, authored SQLite/PostgreSQL SQL and a reference
Store that records artifact evidence metadata and caller-owned workflow bindings.
Artifact bytes live in the caller's object store; storage retains the
content-addressed digest and byte size. Every artifact contract has a durable
SQL projection, and scoped views can compose
bindings with those projections. See the [model and write
semantics](storage/v1/README.md). SQL is grouped by database, entity and operation;
there is no ORM or shipped test corpus.

```python
import sqlite3
from pathlib import Path

from traust_contracts.v1.storage import Binding, Store

conn = sqlite3.connect("traust.db")
try:
    store = Store(conn)
    store.init()
    payload = Path("my-vuln-findings.json").read_bytes()
    result = store.ingest(
        "vuln-findings",
        payload,
        Binding(
            subject_id="sci:inventory-item:42",
            run_id="sci:scan-result:7",
        ),
    )
    print(result.digest, result.binding_id, result.already_bound)
finally:
    conn.close()
```

The caller owns an idle connection and supplies opaque context required by the
artifact's hand-authored storage profile. `scope_id` defaults to `local`.
Ingest validates bytes, computes the digest, stores the evidence record, binding,
and any approved projection in one transaction. Raw payload is not retained in
the database. Identical-binding retries are a no-op.
On `IngestError`, the host MUST surface/preserve `error.payload` (the input file
already on disk suffices). The library never chooses a reject path.

SQLite is complete with stdlib; the caller-selected database file is its
physical namespace. PostgreSQL >=14 uses the optional `postgres` extra
(`psycopg>=3`, requiring libpq or separately installed `psycopg[binary]`). Its
relations live in the fixed `traust_storage` schema, created by `init()` when
absent or provisioned beforehand by restricted deployments. Qualified canonical
SQL prevents application relations and `search_path` from redirecting storage.
The scoped views are live; no refresh worker is needed. PostgreSQL filters by
transaction-local `traust.scope_ids`; callers provision tenant permissions.
Storage-internal foreign keys protect binding/evidence/projection integrity;
cross-artifact domain references remain soft.

Storage compatibility metadata is independent of package semver. `init()` rejects
metadata mismatches and does not migrate existing databases. Edit SQL directly and
review compatibility; SQL is not byte-pinned.
Tests use focused synthetic inputs and test fixtures, not a packaged
conformance bundle.

## Ledger relational contract

`ledger/v1` is the SQL-first Ledger database contract, separate from baseline
`storage/v1`. Contracts owns authored PostgreSQL and SQLite DDL — tables,
constraints, indexes, and **append-only enforcement triggers** — plus
deterministic per-file bootstrap order. No ORM binding is shipped.

Bootstrapping from the contracts SQL alone installs the full append-only
contract: events reject UPDATE, DELETE, truncation, and out-of-order sequence
inserts; layers reject deletion. Ledger runtimes pin a Contracts release and
load SQL for fresh databases, keeping migrations, SQLAlchemy bindings, grants,
and persistence behavior local. `IF NOT EXISTS` / `DROP + CREATE` makes the
ledger's separate guard installation idempotent.

`CONTRACT_VERSION = "v1"`, `REVISION = 1`. The singleton `schema_revision` row
(`id = 1`) records version and `applied_at`; mismatches fail explicitly.
`schemas/v1/layer.schema.json` is the portable complete-layer document contract
across file, SQLite, and PostgreSQL backends.

## Enum registry

`enums/v1/` holds one file per controlled vocabulary. Every string `enum` in
`schemas/v1` and `config/v1` must match a registry file by its exact set of
values; `tests/test_enum_registry.py` enforces this. `ci/enum_registry.py
--write` derives each file's `used_in_schemas`, and `--check` verifies the
rest.

A registry file has `name`, `source_schema`, `description`, `values` and
`used_in_schemas`, plus these optional fields:

| Field | Meaning |
|---|---|
| `definitions` | What each value means; one entry per value |
| `standard` | The standard followed: `name`, `relationship` (`exact` or `adapted`, where adapted needs a `note`) and an optional `url`. Or `{"none": "<why>"}` |
| `deprecated` | For each deprecated value, `replaced_by`: the registry values (`{enum, value}`) that replace it. Several entries split a value across vocabularies; an empty list is a one-way drop, where readers keep the original string. A replacement is never itself deprecated. `"retired": true` marks a value that a major release removed from `values`. |

Vocabulary changes are made in place: new values are added (a minor
release). An old value then goes through two stages:

1. **Deprecated.** It stays in `values`, so the schema still accepts it.
   Readers normalise it to its replacement, and writers stop emitting it.
2. **Retired**, in a major release. It is removed from `values`, so the
   schema rejects new writes. Its `deprecated` entry stays, with
   `"retired": true`, because ledger events keep their original strings for
   good and readers must always be able to normalise them. Rules that depend on other fields, and moves
between fields, are not registry data; they belong in the code or schema
change that needs them.

## Validate an artifact

```bash
python validate.py --schema report myreport.json
python validate.py --list
```

### Canonical-write review candidate

Default schemas preserve historical effort values, free-text roadmap fields
and open extra-property values. The optional `blocked_external` fact is
independent of effort size. Canonical sizes and priority labels are defined in
[`effort`](enums/v1/effort.json) and
[`roadmap_priority`](enums/v1/roadmap-priority.json); no duration thresholds,
urgency policy or automatic legacy-size mappings are defined.

Explicitly select the stricter contract without adding serialized fields:

```bash
python validate.py --schema 'report#/$defs/canonical_write' myreport.json
```

The same `#/$defs/canonical_write` selector exists for `adapter-result`,
`validation`, `pqc-blockers`, `pqc-readiness` and `threat-model`.
The decision tree follows its existing definitions convention:
`pqc-decision-tree#/definitions/canonical_write`.
These fragments preserve existing requiredness and permit only actual boolean
blocking flags, not strings or null. On formerly open objects the default reader
properties remain unconstrained so historical extra values stay readable.
Mitigation and decision-tree rule effort remains required even when blocked;
unknown-size omission is not an approved policy.

This is an unreleased, known-size review candidate, not a producer switch.
Default validator selection is unchanged. Reader normalization, event-identity
gates and affected-contract review still precede writer activation/publication.
Existing report, baseline and event bytes are never rewritten.

Storage revision 3 carries the independent flag in a nullable
`report_finding.blocked_external` INTEGER column on SQLite and PostgreSQL.
True/false project as 1/0; absence remains SQL NULL, including historical
`blocked-external` effort labels with no separately stated flag. No size or
blocking fact is inferred. Existing report JSON remains intact. Initialization
refuses older storage revisions without modifying them; this candidate supplies
no automatic or live database migration.

## Test

```bash
make setup    # uv sync + enable .githooks
make test     # SQLite + schema tests; PG tests included when db-up
```

PostgreSQL e2e:

```bash
make db-up    # start local Postgres container
make test     # includes PG storage + ledger schema tests
make db-down
```

`tests/test_compat.py` gates breaking JSON Schema changes against the change's base on
`main` (the merge-base on a branch, the previous commit on `main`; override with
`CONTRACTS_COMPAT_BASE=<ref>`).
PostgreSQL tests run automatically when `psycopg` and the database are available;
otherwise they skip.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
