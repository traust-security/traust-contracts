-- Primary CWE per finding, never part of identity: drop prohibited and
-- discouraged mappings, most specific abstraction first (variant > base >
-- class > pillar), lowest CWE number breaks ties. A finding whose every CWE
-- is dropped reads NULL.
CREATE OR REPLACE VIEW traust.finding_primary_cwe AS
SELECT fc.finding_id,
       (SELECT c.identifier
          FROM traust.finding_cwe fc2
          JOIN traust.cwe c ON c.id = fc2.cwe_id
         WHERE fc2.finding_id = fc.finding_id
           AND (c.mapping_usage IS NULL
                OR c.mapping_usage NOT IN ('discouraged', 'prohibited'))
         ORDER BY CASE c.abstraction
                    WHEN 'variant' THEN 0
                    WHEN 'base' THEN 1
                    WHEN 'class' THEN 2
                    WHEN 'pillar' THEN 3
                    ELSE 4
                  END,
                  CAST(SUBSTR(c.identifier, 5) AS INTEGER)
         LIMIT 1) AS primary_cwe
FROM (SELECT DISTINCT finding_id FROM traust.finding_cwe) fc;
