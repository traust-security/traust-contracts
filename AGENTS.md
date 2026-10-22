# traust-contracts

Python 3.11+ contract library (`traust_contracts`). Schemas and enums — semver-breaking by default.

Identity vectors are **not** here: the finding-fingerprint suite was retired on 2026-08-18 (only the harness computes identity, so no second-language port needs a shared oracle). Regression fixtures for the recipe live beside the implementation in the ledger package.

- **Before done:** `make lint-fix` then `make test` — CI enforces both; do not skip
- **Lint:** line length 100; ruff E/W/F/I/UP/B/SIM/PTH/RUF (`pyproject.toml`) — `Path` not `os.path`, no bare `except: pass`
- **Commits:** conventional `type(scope): subject` (`feat`, `fix`, `perf`, `chore`, `ci`, …)
- **Releases:** `feat`/`fix`/`perf`/breaking PRs need `make check-release`, `VERSION` + `CHANGELOG.md` bump
- **Compat:** the gate compares schemas with the change's base on `main` (merge-base; `CONTRACTS_COMPAT_BASE=<ref>` overrides). Breaks need a major bump; escape hatch `CONTRACTS_ALLOW_BREAKING=1 uv run pytest tests/ -q`
- **Downstream pin:** `traust-ledger`, `traust-engine`, and `traust` each carry a
  direct `[tool.uv.sources]` pin on this repo (`rev = "<sha>"`, not a tag).
  After merging here, bump the pin to the new commit in all three, `uv lock`,
  and run each repo's own tests before opening its PR. `make
  downstream-chain-pr` scripts this; see [ci/README.md](ci/README.md).
- **Setup:** `make setup` once per clone (hooks). More: [CONTRIBUTING.md](CONTRIBUTING.md), [README.md](README.md)
