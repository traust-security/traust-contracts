-- A repository_ref as shipped in one release: the many-to-many link of the
-- inventory spine.
--
-- Mutable table. Natural key (release_id, repository_ref_id): a ref appears
-- once per release that ships it.
CREATE TABLE IF NOT EXISTS component (
    id TEXT NOT NULL DEFAULT (uuid()),
    release_id TEXT NOT NULL REFERENCES release(id) ON DELETE RESTRICT,
    repository_ref_id TEXT NOT NULL REFERENCES repository_ref(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (release_id, repository_ref_id)
);

-- Keyset pages ordered by creation time, with id breaking ties.
CREATE INDEX IF NOT EXISTS idx_component_created_id
    ON component (created_at, id);

CREATE INDEX IF NOT EXISTS idx_component_repository_ref
    ON component (repository_ref_id);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS component_touch
AFTER UPDATE ON component FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE component SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
