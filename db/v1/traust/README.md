# Storage v1 — the one-owner data model (`traust` namespace)

SQL is the data model (XWING-2363). Each concept has one owner, database-generated
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

## Views

Landed in `views/` (both dialects), load-ordered by `VIEW_ORDER`:

- `decision_at` — each decision with the commit and line it judged
- `current_decision` — per finding: active, recognized validity and severity,
  ranked by explicit E0–E3 strength then occurred/created time, plus the
  strongest active explicit evidence grade; null means no answer
- `current_resolution` — per finding and line: latest resolution and fix ref
- `unowned` — repositories with no current owner
- `ownership_current` — the open ownership row per repository
- `finding_status` — one row per finding: current state on the default line, `is_open` defined once
- `finding_clock` — first/last seen, first decided, closed per finding
- `finding_primary_cwe` — primary CWE (drop prohibited/discouraged, most
  specific abstraction, lowest number)

`current_decision` excludes any decision restated by another decision in the
same finding. Historical `true_positive` / `hardening` read as `confirmed`;
`not_verified`, `corrected`, and unknown validity values do not answer.
Unknown or absent grades rank below E3; no strength comes from actor or source.
Only an exact lowercase `human:` actor or `auto_accept_tier` makes an FP
eligible. When the strongest/latest non-FP answer is E0 `confirmed`, it stays
confirmed until two distinct human actors have active E0 FP statements
strictly after that proof. A newer E0 confirmed proof resets that interval;
auto-accepted machine statements do not count as human signatures.

### Explicit view refresh on an existing database

Updating a contracts dependency alone does **not** upgrade an already-created
view. Before the next validity write against such a database, explicitly apply
the dialect's `views/current_decision.sql` using `bootstrap_statements` inside
one transaction, then commit. Do not rewrite decisions, ledger events, or Merkle
history. This file preserves the existing view columns and dependent views.

PostgreSQL retains `CREATE OR REPLACE VIEW`. SQLite uses `DROP VIEW IF EXISTS`
followed by `CREATE VIEW`: executing only the create statement, or retaining an
old `CREATE VIEW IF NOT EXISTS` definition, cannot refresh the projection.
The existing bootstrap loader already yields both SQLite statements in order,
so fresh bootstrap and an explicit in-place refresh use the same authored file;
no loader/order change or automatic live migration is needed. The transaction
is required to avoid exposing a dropped view if replacement fails, and permits
rolling the refresh back without changing any stored statement.

Everything else a dashboard needs is service-oriented, not a view:
artifact-lane reads through `assessment` → `artifact` (threat, PQC,
compliance, least-privilege, validation detail), SLA policy joined at read
(config), and composite aggregates the findings service composes over these
views. The previous model's views went with its projection model — the old
SQL is recoverable from git history.

Rules, constraints and indexes come from the plan
(`one-owner-scalable-data-model.md`); this README does not restate them.
