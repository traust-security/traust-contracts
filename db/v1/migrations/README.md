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

## Rolling back

There is no database rollback, by design. A deployment rolls back by
redeploying the previous traust-core and traust-contracts pair together:
the database stays forward, the older channel sees stamps beyond its head
as "ahead" (tolerated — nothing pending, nothing refused), and going
forward again later needs nothing. A change to be abandoned permanently is
a new forward script that removes it. A script that declared destructive
work is a one-way door: software rolled back past it may query a shape that
no longer has what it needs — don't.
