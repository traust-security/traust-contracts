-- Temporal repository ownership, mirrored from the deployment's one declared
-- source.
--
-- Mutable table. Current owner: valid_to IS NULL. As of t:
-- valid_from <= t AND (valid_to IS NULL OR valid_to > t). A repository with
-- no open row is unowned - fix at the source, not here.
CREATE TABLE IF NOT EXISTS ownership (
    id TEXT NOT NULL DEFAULT (uuid()),
    repository_id TEXT NOT NULL REFERENCES repository(id) ON DELETE RESTRICT,
    team_id TEXT NOT NULL REFERENCES team(id) ON DELETE RESTRICT,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    CHECK (valid_to IS NULL OR valid_to > valid_from)
);

-- One open row per (repository, team); history stays side by side.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ownership_open
    ON ownership (repository_id, team_id)
    WHERE valid_to IS NULL;

CREATE INDEX IF NOT EXISTS idx_ownership_team
    ON ownership (team_id);

CREATE INDEX IF NOT EXISTS idx_ownership_repository_valid_from
    ON ownership (repository_id, valid_from);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS ownership_touch
AFTER UPDATE ON ownership FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE ownership SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
