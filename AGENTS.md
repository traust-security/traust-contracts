# traust-contracts

Python 3.11+ contract library (`traust_contracts`). Schemas, enums and DDL; traust-core is its consumer.

Identity vectors are **not** here: the finding-fingerprint suite was retired on 2026-08-18 (only the harness computes identity, so no second-language port needs a shared oracle). Regression fixtures for the recipe live beside the implementation in the ledger package.

- **Before done:** `make lint-fix` then `make test` — CI enforces both; do not skip
- **Placement — where things live:** each directory has one job, and every
  file in it must be load-bearing (the delete test: something fails when the
  file is deleted — a test, a loader, a generator; a file nothing reads is
  decoration, however correct it looks).
  - `artifacts_schema/v1/` — documents persisted for the ledger (what skills
    and LLMs consume), validated on write. Never API request/response shapes.
  - `config/v1/` — the configuration contract.
  - `views_schema/v1/` — served view **models**, core validates each at build.
    Never **requests**: a query's shape is core's code (pydantic → OpenAPI →
    the SDK's generated types); duplicating it here is a second source that
    drifts. The SDK builds from OpenAPI — contracts' consumers are the
    ledger's validators, core's loaders, and the DDL channel, never client
    generation.
  - `enums/v1/` — controlled vocabularies with a real consumer: a schema site
    the registry scans, or a DDL/code path that loads the file. A vocabulary
    nothing loads is decoration — core's own enums and the SQL CHECK
    constraints are sources already.
  - `db/v1/` — bootstrap DDL for new stores, the hash-stamped upgrade channel
    for existing ones. CHECK constraints spell their values in the SQL:
    migrations are immutable and read nothing.
  - `mappings/` — cross-vocabulary mapping tables.
- **Data-model changes:** every schema/enum/DDL addition must pass the six
  question litmus test in [README.md](README.md#before-adding-anything-to-the-data-model);
  answer them in the PR description. A change to an existing database's shape
  lands ONLY in the upgrade channel —
  `db/v1/migrations/<dialect>/upgrades/NNNN_slug.sql`, data-preserving, hash-stamped,
  applied by `traust_contracts.v1.migrations`. Destructive SQL (DROP/TRUNCATE/DELETE)
  additionally requires a `-- destructive: <reason>` line - the runner refuses
  to load the script without one. Never a bootstrap-only edit
  (existing databases never see it), never a per-namespace `upgrades/` folder
  (deleted), never a `*_upgrade()` helper (deleted), never a hand-applied ALTER
- **Lint:** line length 100; ruff E/W/F/I/UP/B/SIM/PTH/RUF (`pyproject.toml`) — `Path` not `os.path`, no bare `except: pass`
- **Commits:** conventional `type(scope): subject` (`feat`, `fix`, `perf`, `chore`, `ci`, …)
- **No versions or tags:** traust-core pins this repo by commit SHA
  (`[tool.uv.sources] rev = "<sha>"`). To ship a change: merge here, move
  traust-core's `rev` to the new commit, `uv lock`, run traust-core's tests.
  `make schema-diff` lists schema changes traust-core may need to absorb.
- **Consumers:** traust-core is the hub and the only intended consumer; other
  repos reach the contract through traust-core.
- **Setup:** `make setup` once per clone (hooks). More: [CONTRIBUTING.md](CONTRIBUTING.md), [README.md](README.md)
