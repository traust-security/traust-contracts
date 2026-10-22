-- Revision 5 -> 6: report_finding.owasp_llm_references.
--
-- The report schema declares owasp_llm_references on a finding (OWASP Top
-- 10 for LLM Applications category IDs), and the table carries every field
-- the schema declares, so the column is added here for existing databases.
-- Fresh databases get it from schema/report_finding.sql.
ALTER TABLE traust_storage.report_finding ADD COLUMN IF NOT EXISTS owasp_llm_references JSONB;
