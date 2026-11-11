-- Repositories with no current owner. A repository with no owner in the
-- declared source shows up here; fix it at the source, not in traust.
CREATE VIEW IF NOT EXISTS unowned AS
SELECT r.*
FROM repository r
WHERE NOT EXISTS (
    SELECT 1 FROM ownership o
    WHERE o.repository_id = r.id AND o.valid_to IS NULL
);
