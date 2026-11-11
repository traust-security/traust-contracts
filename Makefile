PYTHON ?= python3
DOCS_DIR ?= ../traust/docs

DB_CONTAINER := traust-postgres
DB_IMAGE := docker.io/library/postgres:16
DB_PORT := 5432

.PHONY: help setup sync hooks lint lint-fix test storage-check db-up db-down docs schema-diff

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup          — uv sync + enable .githooks (run once per clone)"
	@echo "  make sync           — uv sync only"
	@echo "  make hooks          — git config core.hooksPath .githooks"
	@echo "  make lint           — ruff check + format --check"
	@echo "  make lint-fix       — ruff check --fix + format"
	@echo "  make test           — pytest tests, parallel via pytest-xdist (database e2e included when db-up)"
	@echo "  make db-up          — start local database container for e2e tests"
	@echo "  make db-down        — stop and remove the database container"
	@echo "  make schema-diff    — schema changes vs origin/development that traust-core may need to absorb"
	@echo "  make docs           — regenerate DDL model docs (DOCS_DIR=$(DOCS_DIR))"


setup: sync hooks
	@echo "ready — local hooks enabled (.githooks). Bypass: git commit --no-verify"

sync:
	uv sync

hooks:
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff check --fix .
	uv run ruff format .

storage-check:
	uv run pytest tests/test_db_behavior.py -q

test:
	# loadfile: test_db_behavior.py rebuilds fixed Postgres schemas per test,
	# so it must stay on one worker; everything else spreads across workers.
	uv run pytest tests/ -q -n auto --dist loadfile

db-up:
	@if podman container exists $(DB_CONTAINER) 2>/dev/null; then \
		echo "$(DB_CONTAINER) already running"; \
	else \
		podman run --name $(DB_CONTAINER) --rm -d \
			-e POSTGRES_USER=traust \
			-e POSTGRES_PASSWORD=traust-test-only \
			-e POSTGRES_DB=traust_test \
			-p 127.0.0.1:$(DB_PORT):5432 \
			-v traust-postgres-data:/var/lib/postgresql/data \
			$(DB_IMAGE); \
		echo "waiting for database..."; \
		for i in $$(seq 1 30); do \
			podman exec $(DB_CONTAINER) pg_isready -U traust -q 2>/dev/null && break; \
			sleep 1; \
		done; \
		echo "$(DB_CONTAINER) ready on port $(DB_PORT)"; \
	fi

db-down:
	@podman stop $(DB_CONTAINER) 2>/dev/null || true

docs:
	@if [ ! -d "$(DOCS_DIR)" ]; then \
		echo "DOCS_DIR '$(DOCS_DIR)' does not exist; pass DOCS_DIR=/path/to/docs" >&2; \
		exit 1; \
	fi
	uv run python -m traust_contracts.v1.ledger.build_ledger_ddl_model \
		--out "$(DOCS_DIR)/ledger-v1-ddl-model.md"

schema-diff:
	$(PYTHON) ci/schema_diff.py
