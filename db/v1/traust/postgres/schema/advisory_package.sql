-- Which packages a published vulnerability affects: the advisory sweep
-- surface.
--
-- Mutable table. Affected-version ranges stay in the artifact; this row says
-- only "advisory A touches package P".
CREATE TABLE IF NOT EXISTS traust.advisory_package (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    advisory_id UUID NOT NULL REFERENCES traust.advisory(id) ON DELETE RESTRICT,
    package_id UUID NOT NULL REFERENCES traust.package(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (advisory_id, package_id)
);

-- Advisories affecting a package (advisory sweep).
CREATE INDEX IF NOT EXISTS idx_advisory_package_package
    ON traust.advisory_package (package_id);

DROP TRIGGER IF EXISTS advisory_package_touch ON traust.advisory_package;
CREATE TRIGGER advisory_package_touch
BEFORE UPDATE ON traust.advisory_package
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
