-- A label on a finding, from a taxonomy: public catalogs (attack, asvs,
-- cis, slsa, ...) or adopter taxonomies as extensions.
--
-- taxonomy and label are closed per taxonomy (contracts
-- enums/v1/label-taxonomy.json, to add) - checked at intake, not a database
-- constraint. Multi-valued by design: rows, never columns.
CREATE TABLE IF NOT EXISTS traust.finding_label (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES traust.finding(id) ON DELETE RESTRICT,
    taxonomy TEXT NOT NULL CHECK (taxonomy <> ''),
    label TEXT NOT NULL CHECK (label <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (finding_id, taxonomy, label)
);

-- Findings with a label (RBAC tenancy, ATT&CK coverage,
-- compliance).
CREATE INDEX IF NOT EXISTS idx_finding_label_taxonomy_label
    ON traust.finding_label (taxonomy, label);

DROP TRIGGER IF EXISTS finding_label_touch ON traust.finding_label;
CREATE TRIGGER finding_label_touch
BEFORE UPDATE ON traust.finding_label
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
