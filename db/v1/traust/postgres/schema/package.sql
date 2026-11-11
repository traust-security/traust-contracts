-- A third-party or internal package, one per (ecosystem, name).
--
-- Mutable table. source_repository_id: the inventory repository that produces
-- it (internal library); null = third party. sbom_id: an image package's own
-- SBOM (e.g. a base image's OS packages), tracing through Dockerfile FROM.
-- ecosystem classifies, so its values come from a registry - contracts
-- enums/v1/ecosystem.json - checked at intake, not a database constraint.
CREATE TABLE IF NOT EXISTS traust.package (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    source_repository_id UUID REFERENCES traust.repository(id) ON DELETE RESTRICT,
    sbom_id UUID REFERENCES traust.sbom(id) ON DELETE RESTRICT,
    ecosystem TEXT NOT NULL CHECK (ecosystem <> ''),
    name TEXT NOT NULL CHECK (name <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (ecosystem, name)
);

-- Internal libraries a repository produces (transitive blast
-- radius, crown-jewel fan-in).
CREATE INDEX IF NOT EXISTS idx_package_source_repository
    ON traust.package (source_repository_id)
    WHERE source_repository_id IS NOT NULL;

-- Image packages with an SBOM (blast radius through FROM).
CREATE INDEX IF NOT EXISTS idx_package_sbom
    ON traust.package (sbom_id)
    WHERE sbom_id IS NOT NULL;

DROP TRIGGER IF EXISTS package_touch ON traust.package;
CREATE TRIGGER package_touch
BEFORE UPDATE ON traust.package
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
