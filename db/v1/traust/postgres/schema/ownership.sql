-- Temporal repository ownership, mirrored from the deployment's one declared
-- source.
--
-- Mutable table. Current owner: valid_to IS NULL. As of t:
-- valid_from <= t AND (valid_to IS NULL OR valid_to > t). A repository with
-- no open row is unowned - fix at the source, not here.
CREATE TABLE IF NOT EXISTS traust.ownership (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES traust.repository(id) ON DELETE RESTRICT,
    team_id UUID NOT NULL REFERENCES traust.team(id) ON DELETE RESTRICT,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    CHECK (valid_to IS NULL OR valid_to > valid_from)
);

-- One open row per (repository, team); history stays side by side.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ownership_open
    ON traust.ownership (repository_id, team_id)
    WHERE valid_to IS NULL;

CREATE INDEX IF NOT EXISTS idx_ownership_team
    ON traust.ownership (team_id);

CREATE INDEX IF NOT EXISTS idx_ownership_repository_valid_from
    ON traust.ownership (repository_id, valid_from);

DROP TRIGGER IF EXISTS ownership_touch ON traust.ownership;
CREATE TRIGGER ownership_touch
BEFORE UPDATE ON traust.ownership
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
