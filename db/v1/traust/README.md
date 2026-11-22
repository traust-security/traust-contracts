# Storage v1 — the one-owner data model (`traust` namespace)

SQL is the data model. Each concept has one owner, database-generated
identity (UUID v4 — `gen_random_uuid()` on Postgres, `uuid()` on SQLite from
`ext/misc/uuid.c` or a driver-registered function), and real constraints; the
same services run solo (SQLite) and at scale (PostgreSQL). Artifact bytes live
in the caller's object store; the database indexes and relates them. Order
comes from `created_at`, never from the id.

Each namespace of the model owns its own top-level directory and loader:

| Directory | Namespace | Plan sections |
|---|---|---|
| [storage/v1](.) (this directory) | `traust` — domain | 1–3: inventory, dependencies, assessments & findings |
| [db/v1/traust_ops](../traust_ops/) | `traust_ops` — operations | 4: runs, spend, feed snapshots |
| [db/v1/traust_ledger](../traust_ledger/) | `traust_ledger` — ledger | 5: append-only layers and events |

| Database | Driver | Shape |
|---|---|---|
| [SQLite](sqlite/) | Standard-library `sqlite3` | plain core names here; `ops_` / `ledger_` prefixes in the same database file |
| [PostgreSQL 14+](postgres/) | `psycopg>=3` | schemas `traust`, `traust_ops`, `traust_ledger`, cross-schema FKs |

Consumers load each namespace through its own module and compose them:
`traust_contracts.v1.storage.sql`, `traust_contracts.v1.ops.sql`,
`traust_contracts.v1.ledger.sql` — each exposes `bootstrap_files(dialect)` /
`bootstrap_statements(dialect, path)`.

## Status

Landing table by table, one pull-request-sized part per plan section:

- [x] Part 1 — section 1, Inventory: `product`, `release`, `component`,
      `repository`, `repository_ref`, `team`, `ownership`
- [x] Part 2 — section 2, Dependencies: `package`, `sbom`, `dependency`,
      `advisory`, `image`, `advisory_package` — `sbom`, `dependency` and
      `image` are append-only (reject-mutation triggers); the Part 1
      `repository_ref.manifest_sbom_id` FK lands here
- [ ] Part 3 — sections 3a/3b, Assessments & findings
- [ ] Part 4 — section 4, Operations — lands in [db/v1/traust_ops](../traust_ops/)
- [x] Part 5 — section 5, Ledger — reworked in [db/v1/traust_ledger](../traust_ledger/):
      `layers` + `events`, keyed by storage UUIDs

Queries and the write protocol (Store) are out of scope until the DDL lands;
the first view set has landed (below). The previous projection model (its
schema, queries, migrations and Store) was removed with it; databases
created under it are recreated, not migrated.

### Bootstrap constraint corrections

The default-reference and auto-accept CHECKs explicitly reject NULL classification
values when their flags are true. A default reference must be a named branch;
auto-accept requires an assessor's `false_positive` validity. SQL CHECK accepts an
unknown result, so equality alone does not enforce either rule on nullable fields.

These definitions apply when creating tables. Re-running `CREATE TABLE IF NOT
EXISTS` does not replace CHECKs in an existing database. Before relying on these
guards there, arrange an explicit constraint upgrade (PostgreSQL) or a reviewed
table rebuild (SQLite) with the data-model owners. Existing violating rows must
be assessed first; do not silently change classifications or rewrite append-only
decisions to make an upgrade pass. This bootstrap correction does not bump the
database revision or perform a migration.

## Views

Landed in `views/` (both dialects), load-ordered by `VIEW_ORDER`:

- `unowned` — repositories with no current owner
- `ownership_current` — the open ownership row per repository
- `finding_primary_cwe` — primary CWE (drop prohibited/discouraged, most
  specific abstraction, lowest number)

### Retired: the disposition views

`decision_at`, `current_decision`, `current_resolution`, `finding_status` and
`finding_clock` were retired. A finding's state is a policy
(evidence-ranked precedence, two-person sign-off, restatements, per-line
resolution with a comparison's baseline line), so it has one owner: traust-core's
`Disposition.fold`, read through the findings service (`get`, `list`,
`open_count`, `clocks`). Two implementations had drifted (the views ranked
resolution by latest only). `views/retired.sql` drops them from databases an
older contract created; nothing reads them.
