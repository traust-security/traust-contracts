# Migrations v1 — the upgrade channel

Runner-owned SQL for upgrading an existing database: the `db_upgrade` stamp
table and future upgrade scripts (`<dialect>/upgrades/NNNN_slug.sql`). The
current data model is the baseline, so `upgrades/` starts empty.

The channel's contract — naming, ordering, additivity, hash stamps,
recreate-only for pre-runner databases — is written down in
[db/v1/traust/README.md](../traust/README.md#upgrades); the runner is
`traust_contracts.v1.migrations`.
