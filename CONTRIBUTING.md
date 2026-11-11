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

## Shipping a change

No versions, tags or changelog. traust-core pins this repo by commit SHA:
merge here, move traust-core's `rev` to the new commit, `uv lock`, and run
traust-core's tests. `make schema-diff` lists schema changes (removed
properties or enum values, newly required fields) that traust-core may need
to absorb in the same push.

SQL changes require compatibility review, not byte-level equality. Database-shape
changes need a storage revision bump and explicit migration instructions; `init()`
rejects mismatches and never upgrades an existing database automatically.

## CI pipeline

PostgreSQL storage tests use `traust:traust-test-only@127.0.0.1:5432/traust_test`.
Start with `podman pull docker.io/library/postgres:16`, then run the image with those values.
Tests warn and skip when the database or `psycopg` is unavailable.

**PR:** lint → conventional commits → tests

## Running tests

```bash
make test
uv run pytest -q
```

## Architecture

See [README.md](README.md) for versioning axes, validation, and consumption.
