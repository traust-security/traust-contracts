-- A team: the unit ownership rows point at.
--
-- Mutable table. One natural key (name). Ownership has one declared source
-- per deployment; traust mirrors it here and does not reconcile sources.
CREATE TABLE IF NOT EXISTS traust.team (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (name <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (name)
);

DROP TRIGGER IF EXISTS team_touch ON traust.team;
CREATE TRIGGER team_touch
BEFORE UPDATE ON traust.team
FOR EACH ROW EXECUTE FUNCTION traust.touch_updated_at();
