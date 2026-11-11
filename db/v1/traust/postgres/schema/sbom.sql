-- An SBOM: the normalized package list of a source tree or image, deduplicated
-- by content digest. Ingested as CycloneDX / SPDX from standard tools (syft,
-- osv-scanner) or imported - never from custom parsers.
--
-- Append-only: id, created_at and a reject-mutation trigger; corrections are
-- new rows. digest is the sha256 of the normalized package list - not the
-- document, whose bytes change every run (timestamps, serial).
-- artifact_id: the first document seen with this content; its FK lands with
-- the artifact table .
CREATE TABLE IF NOT EXISTS traust.sbom (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    digest TEXT NOT NULL CHECK (digest <> ''),
    artifact_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (digest)
);

DROP TRIGGER IF EXISTS sbom_reject_mutation ON traust.sbom;
CREATE TRIGGER sbom_reject_mutation
BEFORE UPDATE OR DELETE ON traust.sbom
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS sbom_reject_truncate ON traust.sbom;
CREATE TRIGGER sbom_reject_truncate
BEFORE TRUNCATE ON traust.sbom
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
