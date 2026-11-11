-- Something a human must look at, and the decision that answered it.
--
-- Mutable table. reason and status values come from contracts (merged
-- review reasons; pending | accepted | rejected | closed_unreviewed) -
-- checked at intake.
CREATE TABLE IF NOT EXISTS review_item (
    id TEXT NOT NULL DEFAULT (uuid()),
    finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE RESTRICT,
    decision_id TEXT REFERENCES decision(id) ON DELETE RESTRICT,
    resolved_by_decision_id TEXT REFERENCES decision(id) ON DELETE RESTRICT,
    reason TEXT,
    status TEXT NOT NULL CHECK (status <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id)
);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS review_item_touch
AFTER UPDATE ON review_item FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE review_item SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;

-- A finding's review items; the pending review queue.
CREATE INDEX IF NOT EXISTS idx_review_item_finding
    ON review_item (finding_id);
CREATE INDEX IF NOT EXISTS idx_review_item_pending
    ON review_item (created_at)
    WHERE status = 'pending';
