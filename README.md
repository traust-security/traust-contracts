# Traust Contracts

Source of truth for JSON schemas and enums shared across the Traust ecosystem,
plus generated Python bindings, **the configuration contract** (the one place
that knows what config exists and how it loads), and **storage/v1** (the SQL-first
relational contract for the one-owner data model).

## Configuration contract

Contracts owns the configuration *mechanism* for the whole stack — mechanism
only, never estate data:

- **MANIFEST** — the authoritative list of config files (name, required/optional,
  schema, typed model). The single source of truth for “what config exists.”
- **Schemas** — `config/v1/*.schema.json`, applied at load time (versioned
  separately from the `artifacts_schema/v1` schemas).
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
connections; the write protocol (Store) is rebuilt against the new data model.
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

Two axes:

- **Data-contract version** (`v1`, `v2`, ...) — the shape of schemas/enums
  and everything generated from them. Lives as a real directory; `v2` sits
  beside `v1` once it exists.
- **Commit SHA** — the only release identifier. No package versions or tags:
  traust-core pins this repo by commit (`[tool.uv.sources] rev = "<sha>"`).

`traust_contracts.models` / `.enums` / `.paths` alias the current major
(`v1` today). Pin to `traust_contracts.v1.*` directly if the shape must
never move under you.

Finding DTO serialization preserves schema-valid classifier aliases, dependency
provenance and `fingerprint_algo`. Absent, empty defaults for the optional
nonempty-only isolation/PEACH lists stay omitted; explicit values remain
available to the final schema gate, including invalid explicit nulls. These
models are not a new-write admission policy: core validates the final artifact
bytes and owns canonical persistence.

`adapter-result` carries scanner observations, not authored audit findings.
Its adapter-local finding schema preserves shared field validation while
allowing unreported CWEs, description and remediation, and opaque native IDs.
It does not invent classifications or verdicts. `report.schema.json` keeps its
full authored-finding requirements unchanged.

## Pack spec

`config/v1/pack.schema.json` is the shape of a workload pack's `assets.yaml` (the
security pack lives in traust as `packs/security/assets.yaml`). traust-engine plans and
admits from `deps`, `partitions`, `trigger`, `priority`, `freshness` and `admission`;
runners execute from `run`, `params`, `runner`, `model`, `writes`, `riders` and
`outcomes` in their pinned copy. The schema is strict, so a key one reader doesn't know
fails for both.

## Run manifest

`artifacts_schema/v1/run-manifest.schema.json` is the per-order detail that
`run_order.artifact_id` points at: config digests in force (the pack file's digest is the
pack version), the budget verdict at admission, the approval, progress and degraded keys.
Each change is a new artifact; the manifest doesn't name its order, so orders in the same
state share one artifact.

## Storage contract

`artifacts_schema/v1/code-facts.schema.json` defines recorded symbols and measured
language/LoC counters for `tool_scan` assessments. The assessment identifies the
scanned ref and producer. A null section is unmeasured; an empty array is a
measured empty result. This artifact adds no database tables or columns.

`db/v1/traust` is the one-owner data model (XWING-2363): readable, authored
SQLite/PostgreSQL SQL — each concept one owner, database-generated UUID v4
identity (`gen_random_uuid()` / SQLite's `uuid()`), real constraints. Namespaces:
`traust` (domain), `traust_ops` (operations), `traust_ledger` (ledger)
— each owns its top-level directory
(`db/v1/traust`, `db/v1/traust_ops`, `db/v1/traust_ledger`) and loader, with Postgres schemas and
cross-schema FKs, and SQLite table prefixes in one database file. See the
[model README](db/v1/traust/README.md).

```python
import sqlite3

from traust_contracts.v1.storage.sql import bootstrap_files, bootstrap_statements

conn = sqlite3.connect("traust.db")
conn.execute("PRAGMA foreign_keys = ON")
for path in bootstrap_files("sqlite"):
    for statement in bootstrap_statements("sqlite", path):
        conn.execute(statement)
```

SQLite is complete with stdlib; the caller-selected database file is its
physical namespace. PostgreSQL >=14 uses the optional `postgres` extra
(`psycopg>=3`, requiring libpq or separately installed `psycopg[binary]`).

The model lands part by part (see the [status table](db/v1/traust/README.md));
queries, views and the write protocol (Store) follow once the DDL has landed.
The previous projection model was removed with this revision — databases
created under it are recreated, not migrated.

## Ledger relational contract

`db/v1/traust_ledger` is the `traust_ledger` namespace of the one-owner data model:
append-only proof of decisions. `layers` — one per repository, or one per
branch line — carry the Merkle root, epoch, size and signature; `events` —
one per decision, `UNIQUE (decision_id)` — carry the opaque, signed payload
and the layer sequence. The traust-ledger library computes and signs; the
app stores. Optional: off means no proof, never broken queries.

Contracts owns the authored DDL — tables, constraints, indexes and
append-only enforcement triggers — plus deterministic bootstrap order.
Bootstraps after `db/v1/traust`: layers and events reference `repository`,
`repository_ref` and `decision` there. SQLite: `ledger_` table prefixes in
the same database file. `CONTRACT_VERSION = "v1"`, `REVISION = 1`;
databases created under the earlier ledger are recreated, not migrated.

## Enum registry

`enums/v1/` holds one file per controlled vocabulary. Every string `enum` in
`artifacts_schema/v1` and `config/v1` must match a registry file by its exact set of
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

`make schema-diff` reports schema changes vs `origin/development` that traust-core may need to absorb.
PostgreSQL tests run automatically when `psycopg` and the database are available;
otherwise they skip.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
