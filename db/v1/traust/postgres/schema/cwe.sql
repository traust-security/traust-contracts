-- CWE identifiers findings report. A row is recorded at intake for each
-- well-formed identifier (CWE-306), as the report schemas checked.
--
-- Mutable table. abstraction, mapping_usage and catalog_version are optional
-- MITRE catalog enrichment (closed catalog values when loaded; no loader yet):
-- they refine the finding_primary_cwe ranking and stay null until then.
CREATE TABLE IF NOT EXISTS traust.cwe (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    identifier TEXT NOT NULL CHECK (identifier <> ''),
    abstraction TEXT,
    mapping_usage TEXT,
    catalog_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (identifier)
);

DROP TRIGGER IF EXISTS cwe_touch ON traust.cwe;
CREATE TRIGGER cwe_touch
BEFORE UPDATE ON traust.cwe
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
