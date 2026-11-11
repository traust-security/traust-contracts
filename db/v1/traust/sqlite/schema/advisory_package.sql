-- Which packages a published vulnerability affects: the advisory sweep
-- surface.
--
-- Mutable table. Affected-version ranges stay in the artifact; this row says
-- only "advisory A touches package P".
CREATE TABLE IF NOT EXISTS advisory_package (
    id TEXT NOT NULL DEFAULT (uuid()),
    advisory_id TEXT NOT NULL REFERENCES advisory(id) ON DELETE RESTRICT,
    package_id TEXT NOT NULL REFERENCES package(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (advisory_id, package_id)
);

-- Advisories affecting a package (advisory sweep).
CREATE INDEX IF NOT EXISTS idx_advisory_package_package
    ON advisory_package (package_id);

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS advisory_package_touch
AFTER UPDATE ON advisory_package FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE advisory_package SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
