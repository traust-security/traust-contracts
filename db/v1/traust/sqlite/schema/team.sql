-- A team: the unit ownership rows point at.
--
-- Mutable table. One natural key (name). Ownership has one declared source
-- per deployment; traust mirrors it here and does not reconcile sources.
CREATE TABLE IF NOT EXISTS team (
    id TEXT NOT NULL DEFAULT (uuid()),
    name TEXT NOT NULL CHECK (name <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (name)
);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS team_touch
AFTER UPDATE ON team FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE team SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
