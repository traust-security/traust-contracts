-- A third-party or internal package, one per (ecosystem, name).
--
-- Mutable table. source_repository_id: the inventory repository that produces
-- it (internal library); null = third party. sbom_id: an image package's own
-- SBOM (e.g. a base image's OS packages), tracing through Dockerfile FROM.
-- ecosystem classifies, so its values come from a registry - contracts
-- enums/v1/ecosystem.json - checked at intake, not a database constraint.
CREATE TABLE IF NOT EXISTS package (
    id TEXT NOT NULL DEFAULT (uuid()),
    source_repository_id TEXT REFERENCES repository(id) ON DELETE RESTRICT,
    sbom_id TEXT REFERENCES sbom(id) ON DELETE RESTRICT,
    ecosystem TEXT NOT NULL CHECK (ecosystem <> ''),
    name TEXT NOT NULL CHECK (name <> ''),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (ecosystem, name)
);

-- Internal libraries a repository produces (transitive blast
-- radius, crown-jewel fan-in).
CREATE INDEX IF NOT EXISTS idx_package_source_repository
    ON package (source_repository_id)
    WHERE source_repository_id IS NOT NULL;

-- Image packages with an SBOM (blast radius through FROM).
CREATE INDEX IF NOT EXISTS idx_package_sbom
    ON package (sbom_id)
    WHERE sbom_id IS NOT NULL;

-- The database owns updated_at; the guard keeps it stable under recursive
-- triggers and respects a manually set value.
CREATE TRIGGER IF NOT EXISTS package_touch
AFTER UPDATE ON package FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE package SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
