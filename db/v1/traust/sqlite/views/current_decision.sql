-- Per finding: active, recognized answers, strongest explicit E0..E3 first,
-- then latest occurred_at / created_at. Null and unknown grades are weakest;
-- neither actor nor source supplies evidence strength. Restatements remove
-- their target only within this finding, including historical aliases.
--
-- Refresh explicitly in a transaction: SQLite cannot CREATE OR REPLACE VIEW.
-- The bootstrap loader already executes both statements in file order.
DROP VIEW IF EXISTS current_decision;
CREATE VIEW current_decision AS
SELECT f.id AS finding_id,
       (WITH active AS (
            SELECT CASE d.validity
                       WHEN 'true_positive' THEN 'confirmed'
                       WHEN 'hardening' THEN 'confirmed'
                       WHEN 'confirmed' THEN 'confirmed'
                       WHEN 'false_positive' THEN 'false_positive'
                       WHEN 'not_affected' THEN 'not_affected'
                   END AS validity,
                   CASE d.evidence_grade
                       WHEN 'E0' THEN 0 WHEN 'E1' THEN 1
                       WHEN 'E2' THEN 2 WHEN 'E3' THEN 3 ELSE 4
                   END AS strength,
                   substr(d.actor, 1, 6) = 'human:' AS human,
                   d.actor, d.auto_accept_tier, d.occurred_at, d.created_at
              FROM decision d
             WHERE d.finding_id = f.id
               AND NOT EXISTS (
                   SELECT 1 FROM decision r
                    WHERE r.finding_id = d.finding_id AND r.restates_id = d.id
               )
        ), proof AS (
            SELECT validity, strength, occurred_at FROM active
             WHERE validity IN ('confirmed', 'not_affected')
             ORDER BY strength, occurred_at DESC, created_at DESC LIMIT 1
        )
        SELECT CASE
            -- An active execution proof needs two distinct later E0 humans.
            -- Auto-accepted machine FPs cannot supply either signature.
            WHEN EXISTS (SELECT 1 FROM proof WHERE strength = 0 AND validity = 'confirmed')
            THEN CASE WHEN (
                SELECT COUNT(*) FROM (
                    SELECT DISTINCT actor FROM active
                     WHERE validity = 'false_positive' AND human AND strength = 0
                       AND occurred_at > (SELECT occurred_at FROM proof)
                     LIMIT 2
                ) signers
            ) >= 2 THEN 'false_positive' ELSE 'confirmed' END
            ELSE (SELECT validity FROM active
                   WHERE validity IN ('confirmed', 'not_affected')
                      OR (validity = 'false_positive' AND (human OR auto_accept_tier))
                   ORDER BY strength, occurred_at DESC, created_at DESC LIMIT 1)
        END) AS validity,
       (SELECT d.severity
          FROM decision d
         WHERE d.finding_id = f.id
           AND d.severity IN ('critical', 'high', 'medium', 'low', 'informational')
           AND NOT EXISTS (
               SELECT 1 FROM decision r
                WHERE r.finding_id = d.finding_id AND r.restates_id = d.id
           )
         ORDER BY CASE d.evidence_grade
                      WHEN 'E0' THEN 0 WHEN 'E1' THEN 1
                      WHEN 'E2' THEN 2 WHEN 'E3' THEN 3 ELSE 4
                  END, d.occurred_at DESC, d.created_at DESC LIMIT 1) AS severity,
       (SELECT d.evidence_grade
          FROM decision d
         WHERE d.finding_id = f.id AND d.evidence_grade IN ('E0', 'E1', 'E2', 'E3')
           AND NOT EXISTS (
               SELECT 1 FROM decision r
                WHERE r.finding_id = d.finding_id AND r.restates_id = d.id
           )
         ORDER BY CASE d.evidence_grade
                      WHEN 'E0' THEN 0 WHEN 'E1' THEN 1
                      WHEN 'E2' THEN 2 WHEN 'E3' THEN 3
                  END, d.occurred_at DESC, d.created_at DESC LIMIT 1) AS evidence_grade
FROM finding f
WHERE EXISTS (SELECT 1 FROM decision d WHERE d.finding_id = f.id);
