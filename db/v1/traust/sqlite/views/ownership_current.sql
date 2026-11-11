-- Current owner per repository: the open ownership row (valid_to IS NULL),
-- with the team a dashboard cuts by. As of t instead:
-- valid_from <= t AND (valid_to IS NULL OR valid_to > t).
CREATE VIEW IF NOT EXISTS ownership_current AS
SELECT o.repository_id,
       r.url AS repository_url,
       o.team_id,
       t.name AS team,
       o.valid_from
FROM ownership o
JOIN repository r ON r.id = o.repository_id
JOIN team t ON t.id = o.team_id
WHERE o.valid_to IS NULL;
