# Migrations v1 — the upgrade channel

Runner-owned SQL for upgrading an existing database: the `db_upgrade` stamp
table and the channel's upgrade scripts
(`<dialect>/upgrades/NNNN_slug.sql`). The current data model is the baseline
plus the channel: `0001_repository_disposition.sql` is the first script — the
unreachable-disposition columns, which the baseline schema files no longer
carry so fresh and upgraded databases take the same path.

The channel's contract — naming, ordering, additivity, hash stamps,
pre-channel stores stamped on at the head — is written down in
[db/v1/traust/README.md](../traust/README.md#upgrades); the runner is
`traust_contracts.v1.migrations`.

## Rolling out fenced leases (`0004_run_order_lease_generation.sql`)

- **Fresh database:** bootstrap the namespaces, then run the whole channel. The
  baseline does not contain `lease_generation` or `completed_by`.
- **Already stamped at `0003`:** stop old writers. With the new Core/contracts
  pair, run `traust-server --config traust.yaml db upgrade` and confirm only
  `0004_run_order_lease_generation` is pending; rerun with `--apply`.
- **Populated but not enrolled:** stamping establishes a presumed schema, it
  does not run SQL. If the store has the `0003` shape but no `db_upgrade`
  table, use the **`0003` Core/contracts pair** to plan and `--apply` enrollment
  first. Confirm `0001`–`0003` are stamped, then follow the
  preceding step. Do not stamp such a store with the `0004` pair: that would
  mark all four scripts applied without adding the lease columns.

The upgrade preserves every order and its lease expiry. Generation zero means
no fenced claim was issued: it cannot authorize writes, even for a legacy
order still marked `leased`. Let that lease expire and reclaim it; the new
claim issues a positive generation. Historical completions have no recorded
`completed_by` worker and cannot be replayed as that worker.

## Rolling back

There is no database rollback, by design. A deployment rolls back by
redeploying the previous traust-core and traust-contracts pair together:
the database stays forward, the older channel sees stamps beyond its head
as "ahead" (tolerated — nothing pending, nothing refused), and going
forward again later needs nothing. A change to be abandoned permanently is
a new forward script that removes it. A script that declared destructive
work is a one-way door: software rolled back past it may query a shape that
no longer has what it needs — don't.
