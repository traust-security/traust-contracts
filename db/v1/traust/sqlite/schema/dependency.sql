-- One package at one version inside one SBOM.
--
-- Append-only: a changed SBOM is a new sbom row with new dependency rows;
-- corrections are never updates. Grows only when an SBOM's contents change -
-- deduplicated by digest.
CREATE TABLE IF NOT EXISTS dependency (
    id TEXT NOT NULL DEFAULT (uuid()),
    sbom_id TEXT NOT NULL REFERENCES sbom(id) ON DELETE RESTRICT,
    package_id TEXT NOT NULL REFERENCES package(id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (version <> ''),
    direct BOOLEAN NOT NULL CHECK (direct IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (sbom_id, package_id, version)
);

-- SBOMs that include a package (advisory sweep, usage query).
CREATE INDEX IF NOT EXISTS idx_dependency_package
    ON dependency (package_id);

CREATE TRIGGER IF NOT EXISTS dependency_reject_update
BEFORE UPDATE ON dependency BEGIN
  SELECT RAISE(ABORT, 'dependency rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS dependency_reject_delete
BEFORE DELETE ON dependency BEGIN
  SELECT RAISE(ABORT, 'dependency rows are append-only');
END;
