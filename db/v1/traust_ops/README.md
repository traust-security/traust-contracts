# Ops v1 — the `traust_ops` namespace

traust's own operational record: what it ran, with what, and what it cost —
`run_batch`, `run_order`, `spend_event`, `feed_snapshot`, `assessment_input`.
Written by continuous ops; app state, not domain truth.

| Database | Namespaces |
|---|---|
| [SQLite](sqlite/) | `ops_` table prefix, bootstrapped into the same database file as the `traust` namespace |
| [PostgreSQL 14+](postgres/) | `traust_ops` schema |

Loads through `traust_contracts.v1.ops.sql`:
`bootstrap_files(dialect)` / `bootstrap_statements(dialect, path)`.

**Status:** tables landed (`run_batch`, `run_order`, `spend_event`,
`feed_snapshot`, `assessment_input`); `run_order.sql` closes the cross-
namespace cycle by adding `assessment.run_order_id`'s FK on Postgres.
