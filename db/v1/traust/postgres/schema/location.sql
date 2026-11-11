-- Where an occurrence sits: path relative to the occurrence's commit.
--
-- Append-only. line_start / line_end are null together (null = whole file);
-- single line = start. language is set from the path at intake (Linguist
-- map, pinned) - SARIF sourceLanguage; symbol is the enclosing function /
-- method from the symbol index - SARIF logicalLocations.
CREATE TABLE IF NOT EXISTS traust.location (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    occurrence_id UUID NOT NULL REFERENCES traust.occurrence(id) ON DELETE RESTRICT,
    path TEXT NOT NULL CHECK (path <> ''),
    line_start INTEGER,
    line_end INTEGER,
    language TEXT,
    symbol TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    CHECK (line_start IS NULL OR line_start >= 1),
    CHECK ((line_start IS NULL) = (line_end IS NULL)),
    CHECK (line_end IS NULL OR line_end >= line_start)
);

-- One location per occurrence, path and line range; whole-file locations
-- dedupe on path alone.
CREATE UNIQUE INDEX IF NOT EXISTS uq_location_range
    ON traust.location (occurrence_id, path, line_start, line_end)
    WHERE line_start IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_location_file
    ON traust.location (occurrence_id, path)
    WHERE line_start IS NULL;

-- Precedents: the same enclosing function in any repository (the reader then
-- compares vendor-normalized paths). Most locations have no symbol.
DROP INDEX IF EXISTS traust.idx_location_symbol;
CREATE INDEX IF NOT EXISTS idx_location_symbol_page
    ON traust.location (symbol, id)
    WHERE symbol IS NOT NULL;

DROP TRIGGER IF EXISTS location_reject_mutation ON traust.location;
CREATE TRIGGER location_reject_mutation
BEFORE UPDATE OR DELETE ON traust.location
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS location_reject_truncate ON traust.location;
CREATE TRIGGER location_reject_truncate
BEFORE TRUNCATE ON traust.location
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
