-- A ledger layer: one Merkle tree of decision events for one repository,
-- optionally one line (branch layers), signed at each root. line is the branch
-- name - a line is (repository_id, name) of repository_ref, derived, no table;
-- null = repository layer.
--
-- Mutable table: root, epoch and size advance as events append - the
-- traust-ledger library computes, the app stores. Merkle fields are null
-- until the first event is signed. merkle_frontier is the tree's right edge
-- (traust-ledger extend_frontier): the hex roots of its perfect subtrees,
-- largest first, comma-separated, one per set bit of merkle_size; appends
-- extend it without reading earlier events. Null = not computed yet.
CREATE TABLE IF NOT EXISTS traust_ledger.layers (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES traust.repository(id) ON DELETE RESTRICT,
    line TEXT CHECK (line <> ''),
    merkle_root TEXT,
    merkle_epoch INTEGER,
    merkle_size INTEGER,
    merkle_root_signature TEXT,
    merkle_signing_method TEXT NOT NULL CHECK (merkle_signing_method <> ''),
    merkle_signature_format INTEGER,
    merkle_frontier TEXT CHECK (merkle_frontier <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id)
);

-- A repository's ledger layers (append / verify).
CREATE INDEX IF NOT EXISTS idx_ledger_layers_repository
    ON traust_ledger.layers (repository_id);

-- One chain per (repository, line): appends join it, so a second would split the proof.
-- line is nullable and NULLs never collide in a unique key, so the repository layer gets
-- its own partial index.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ledger_layers_repository
    ON traust_ledger.layers (repository_id)
    WHERE line IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ledger_layers_line
    ON traust_ledger.layers (repository_id, line)
    WHERE line IS NOT NULL;

DROP TRIGGER IF EXISTS layers_touch ON traust_ledger.layers;
CREATE TRIGGER layers_touch
BEFORE UPDATE ON traust_ledger.layers
FOR EACH ROW EXECUTE FUNCTION traust_ledger.touch_updated_at();
