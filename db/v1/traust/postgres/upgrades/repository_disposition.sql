-- Explicit additive upgrade for existing databases missing the disposition
-- columns (foundry plan repo-unreachable). Existing repositories are active:
-- disposition stays NULL and the streak starts at 0; the first two gone-class
-- observation failures after the upgrade flip a repository, exactly as a
-- repository registered under the new schema would flip.
ALTER TABLE traust.repository
    ADD COLUMN disposition TEXT CHECK (disposition IS NULL OR disposition = 'repo_unreachable');

ALTER TABLE traust.repository
    ADD COLUMN disposition_reason TEXT CHECK (
        disposition_reason IS NULL
        OR disposition_reason IN ('gone', 'empty', 'unreachable')
    );

ALTER TABLE traust.repository
    ADD COLUMN disposition_evidence TEXT;

ALTER TABLE traust.repository
    ADD COLUMN disposition_at TIMESTAMPTZ;

ALTER TABLE traust.repository
    ADD COLUMN gone_streak INTEGER NOT NULL DEFAULT 0 CHECK (gone_streak >= 0);
