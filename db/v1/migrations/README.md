# Migrations v1 — the upgrade channel

Runner-owned SQL for upgrading an existing database: the `db_upgrade` stamp
table and the channel's upgrade scripts
(`<dialect>/upgrades/NNNN_slug.sql`). The current data model is the baseline
plus the channel: `0001_repository_disposition.sql` is the first script — the
unreachable-disposition columns, which the baseline schema files no longer
carry so fresh and upgraded databases take the same path.

The channel's contract — naming, ordering, additivity, hash stamps,
recreate-only for pre-runner databases — is written down in
[db/v1/traust/README.md](../traust/README.md#upgrades); the runner is
`traust_contracts.v1.migrations`.
