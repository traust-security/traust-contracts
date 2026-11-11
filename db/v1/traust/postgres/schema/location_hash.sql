CREATE TABLE IF NOT EXISTS traust.location_hash (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    location_id UUID NOT NULL REFERENCES traust.location(id) ON DELETE RESTRICT,
    algorithm TEXT NOT NULL CHECK (algorithm <> ''),
    digest TEXT NOT NULL CHECK (digest <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (id),
    UNIQUE (location_id, algorithm),
    CHECK (algorithm <> 'file-bytes-sha256/v1' OR digest ~ '^[0-9a-f]{64}$')
);

DROP TRIGGER IF EXISTS location_hash_reject_mutation ON traust.location_hash;
CREATE TRIGGER location_hash_reject_mutation
BEFORE UPDATE OR DELETE ON traust.location_hash
FOR EACH ROW EXECUTE FUNCTION traust.reject_mutation();

DROP TRIGGER IF EXISTS location_hash_reject_truncate ON traust.location_hash;
CREATE TRIGGER location_hash_reject_truncate
BEFORE TRUNCATE ON traust.location_hash
FOR EACH STATEMENT EXECUTE FUNCTION traust.reject_mutation();
