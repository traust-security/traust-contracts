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

Schema changes to an existing database land in the upgrade channel —
[db/v1/traust/README.md](../traust/README.md#upgrades).

**Status:** tables landed (`run_batch`, `run_order`, `spend_event`,
`feed_snapshot`, `assessment_input`); `run_order.sql` closes the cross-
namespace cycle by adding `assessment.run_order_id`'s FK on Postgres.

Global order-history reads use `(created_at, id)` or two nulls-last
started-time segments: `(started_at, id)` for known times, then `id` for
unknown times. Both directions use the same indexes. These additive,
idempotent bootstrap indexes do not change rows or provide indexed arbitrary
substring search or every selectable sort.

For an existing SQLite database, explicitly apply only the three additive
`CREATE INDEX IF NOT EXISTS` statements from `sqlite/schema/run_order.sql`
during an application write-maintenance window.

For a live PostgreSQL database, use the following statements individually,
outside any transaction, rather than reapplying bootstrap DDL. Ordinary
`CREATE INDEX` blocks order writers for the duration of its build.

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ops_run_order_created
    ON traust_ops.run_order (created_at, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ops_run_order_started
    ON traust_ops.run_order (started_at, id)
    WHERE started_at IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ops_run_order_unstarted
    ON traust_ops.run_order (id)
    WHERE started_at IS NULL;
```

Verify all three indexes before enabling indexed history reads:

```sql
SELECT indexrelid::regclass, indisvalid, indisready
FROM pg_index
WHERE indrelid = 'traust_ops.run_order'::regclass
  AND indexrelid::regclass::text IN (
      'traust_ops.idx_ops_run_order_created',
      'traust_ops.idx_ops_run_order_started',
      'traust_ops.idx_ops_run_order_unstarted');
```

All three must be present, valid and ready. An interrupted concurrent build
can leave an invalid index, and `IF NOT EXISTS` does not repair it. After
confirming that an affected named index is invalid and no build remains
active, drop only that invalid index with `DROP INDEX CONCURRENTLY`, outside
a transaction, then rerun its create statement and verify again. Do not
drop a valid index or assume an existing name proves a successful build.
If concurrent creation cannot be used, schedule an explicit order-write
maintenance window instead. Bootstrap is not an automatic upgrade runner.
