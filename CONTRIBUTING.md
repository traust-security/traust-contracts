# Contributing

## Setup

```bash
git clone <repo-url> && cd traust-contracts
make setup
```

Installs deps (`uv sync`) and enables git hooks. One time per clone.

## Commit messages

Conventional commits required. Format: `type(scope): subject`

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `ci`, `build`, `style`, `revert`

```
feat(schemas): add layer review queue reason
fix(enums): correct disposition resolution label
feat!: bump data-contract v2          ← breaking change
```

## Hooks

| Hook | Runs | Speed |
|------|------|-------|
| `commit-msg` | subject format check | instant |
| `pre-commit` | ruff lint on staged `.py` | <1s |
| `pre-push` | full lint + unit tests | ~10s |

Bypass: `--no-verify` on commit or push. CI still enforces.

## Releasing

If your PR has `feat:`, `fix:`, `perf:`, or `!` (breaking) commits:

```bash
make bump minor
# add ## [X.Y.Z] section to CHANGELOG.md
make check-release
git add VERSION pyproject.toml CHANGELOG.md uv.lock
git commit -m "chore: release X.Y.Z"
```

Run `uv lock` when changing dependencies. Consumers pin contracts by commit SHA.

## Compatibility tests

`tests/test_compat.py` gates breaking JSON Schema changes against the change's base
on `main`: the merge-base with `origin/main` on a branch, the previous commit on
`main` itself. `CONTRACTS_COMPAT_BASE=<ref>` compares against any other ref. For
intentional major bumps:

```bash
CONTRACTS_ALLOW_BREAKING=1 uv run pytest tests/ -q
```

SQL changes require compatibility review, not byte-level equality. Database-shape
changes need a storage revision bump and explicit migration instructions; `init()`
rejects mismatches and never upgrades an existing database automatically.

## CI pipeline

PostgreSQL storage tests use `traust:traust-test-only@127.0.0.1:5432/traust_test`.
Start with `podman pull docker.io/library/postgres:16`, then run the image with those values.
Tests warn and skip when the database or `psycopg` is unavailable.

**PR:** lint → conventional commits → release-ready → tests

**Main:** tag if `VERSION` > latest git tag

## Downstream pins

Consumers pin this repo by commit sha (`[tool.uv.sources] rev = "<sha>"`), not
a release tag — a tag needs this repo's own release cut first, a commit
doesn't. After your change merges to main, bump the pin to the new commit in
each direct downstream repo's `pyproject.toml`, `uv lock`, and run that
repo's own tests before opening its PR.

Direct downstream: `traust-ledger`, `traust-engine`, `traust` (all three pin
this repo directly, not just transitively through ledger/engine).

The mechanical part of this — pin, `uv lock`, test, commit — is scripted:
`make downstream-chain-pr` walks all three hops, test-gating each one on the
repo's own `make test`, and opens a PR against `traust-security/*` at each.
See [`ci/README.md`](ci/README.md) (`ci/bump_downstream.py`) for the full
command list and how it handles forks, squash merges, and resuming a failed
hop.

## Running tests

```bash
make test
uv run pytest -q
```

## Architecture

See [README.md](README.md) for versioning axes, validation, and consumption.
