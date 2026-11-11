-- A repository_ref as shipped in one release: the many-to-many link of the
-- inventory spine.
--
-- Mutable table. Natural key (release_id, repository_ref_id): a ref appears
-- once per release that ships it.
CREATE TABLE IF NOT EXISTS traust.component (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    release_id UUID NOT NULL REFERENCES traust.release(id) ON DELETE RESTRICT,
    repository_ref_id UUID NOT NULL REFERENCES traust.repository_ref(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (release_id, repository_ref_id)
);

-- Keyset pages ordered by creation time, with id breaking ties.
CREATE INDEX IF NOT EXISTS idx_component_created_id
    ON traust.component (created_at, id);

CREATE INDEX IF NOT EXISTS idx_component_repository_ref
    ON traust.component (repository_ref_id);

DROP TRIGGER IF EXISTS component_touch ON traust.component;
CREATE TRIGGER component_touch
BEFORE UPDATE ON traust.component
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
