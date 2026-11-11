-- A named batch of orders: one tranche per (kind, period), e.g. one
-- drain_tranche per ISO week (2026-W31).
--
-- Mutable table. kind is a pack asset name from assets.yaml (drain_tranche,
-- router_run, feeds_refresh) - pack vocabulary, never a core enum, checked
-- at intake.
CREATE TABLE IF NOT EXISTS ops_run_batch (
    id TEXT NOT NULL DEFAULT (uuid()),
    kind TEXT NOT NULL CHECK (kind <> ''),
    period TEXT NOT NULL CHECK (period <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (kind, period)
);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS ops_run_batch_touch
AFTER UPDATE ON ops_run_batch FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE ops_run_batch SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
