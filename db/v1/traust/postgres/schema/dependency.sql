-- One package at one version inside one SBOM.
--
-- Append-only: a changed SBOM is a new sbom row with new dependency rows;
-- corrections are never updates. Grows only when an SBOM's contents change -
-- deduplicated by digest.
CREATE TABLE IF NOT EXISTS traust.dependency (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    sbom_id UUID NOT NULL REFERENCES traust.sbom(id) ON DELETE RESTRICT,
    package_id UUID NOT NULL REFERENCES traust.package(id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (version <> ''),
    direct BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (sbom_id, package_id, version)
);

-- SBOMs that include a package (advisory sweep, usage query).
CREATE INDEX IF NOT EXISTS idx_dependency_package
    ON traust.dependency (package_id);

DROP TRIGGER IF EXISTS dependency_reject_mutation ON traust.dependency;
CREATE TRIGGER dependency_reject_mutation
BEFORE UPDATE OR DELETE ON traust.dependency
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS dependency_reject_truncate ON traust.dependency;
CREATE TRIGGER dependency_reject_truncate
BEFORE TRUNCATE ON traust.dependency
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
