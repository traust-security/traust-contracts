-- An SBOM: the normalized package list of a source tree or image, deduplicated
-- by content digest. Ingested as CycloneDX / SPDX from standard tools (syft,
-- osv-scanner) or imported - never from custom parsers.
--
-- Append-only: id, created_at and a reject-mutation trigger; corrections are
-- new rows. digest is the sha256 of the normalized package list - not the
-- document, whose bytes change every run (timestamps, serial).
-- artifact_id: the first document seen with this content. This FK closes a
-- cycle (sbom -> artifact -> assessment -> image -> sbom); SQLite does not
-- check parent existence at CREATE, so it is inline here and an ALTER in
-- artifact.sql on Postgres.
CREATE TABLE IF NOT EXISTS sbom (
    id TEXT NOT NULL DEFAULT (uuid()),
    digest TEXT NOT NULL CHECK (digest <> ''),
    artifact_id TEXT REFERENCES artifact(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (id),
    UNIQUE (digest)
);

CREATE TRIGGER IF NOT EXISTS sbom_reject_update
BEFORE UPDATE ON sbom BEGIN
  SELECT RAISE(ABORT, 'sbom rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS sbom_reject_delete
BEFORE DELETE ON sbom BEGIN
  SELECT RAISE(ABORT, 'sbom rows are append-only');
END;
