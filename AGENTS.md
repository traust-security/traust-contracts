# traust-contracts

Python 3.11+ contract library (`traust_contracts`). Schemas, enums and DDL; traust-core is its consumer.

Identity vectors are **not** here: the finding-fingerprint suite was retired on 2026-08-18 (only the harness computes identity, so no second-language port needs a shared oracle). Regression fixtures for the recipe live beside the implementation in the ledger package.

- **Before done:** `make lint-fix` then `make test` — CI enforces both; do not skip
- **Data-model changes:** every schema/enum/DDL addition must pass the six
  question litmus test in [README.md](README.md#before-adding-anything-to-the-data-model);
  answer them in the PR description
- **Lint:** line length 100; ruff E/W/F/I/UP/B/SIM/PTH/RUF (`pyproject.toml`) — `Path` not `os.path`, no bare `except: pass`
- **Commits:** conventional `type(scope): subject` (`feat`, `fix`, `perf`, `chore`, `ci`, …)
- **No versions or tags:** traust-core pins this repo by commit SHA
  (`[tool.uv.sources] rev = "<sha>"`). To ship a change: merge here, move
  traust-core's `rev` to the new commit, `uv lock`, run traust-core's tests.
  `make schema-diff` lists schema changes traust-core may need to absorb.
- **Consumers:** traust-core is the hub and the only intended consumer; other
  repos reach the contract through traust-core.
- **Setup:** `make setup` once per clone (hooks). More: [CONTRIBUTING.md](CONTRIBUTING.md), [README.md](README.md)
