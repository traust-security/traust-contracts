-- The channel's first script: the unreachable disposition (foundry plan
-- repo-unreachable). disposition NULL = active, the only value so far is
-- 'repo_unreachable' - the repository left the planner's universe after two
-- consecutive gone-class observation failures and returns only through a
-- person's verify. reason names the class (gone: the forge's 404/410; empty:
-- answered but no commits; unreachable: the transport's positive word the
-- endpoint is not there), evidence carries the last error, and gone_streak
-- counts the consecutive gone-class failures (reset to 0 by any successful
-- observation; the transient classes never count).
--
-- Additive only: existing repositories are active - disposition stays NULL
-- and the streak starts at 0; the first two gone-class observation failures
-- after the upgrade flip a repository, exactly as a repository registered
-- after the upgrade would flip. No data is lost, none is invented.
ALTER TABLE repository
    ADD COLUMN disposition TEXT CHECK (disposition IS NULL OR disposition = 'repo_unreachable');

ALTER TABLE repository
    ADD COLUMN disposition_reason TEXT CHECK (
        disposition_reason IS NULL
        OR disposition_reason IN ('gone', 'empty', 'unreachable')
    );

ALTER TABLE repository
    ADD COLUMN disposition_evidence TEXT;

ALTER TABLE repository
    ADD COLUMN disposition_at TEXT;

ALTER TABLE repository
    ADD COLUMN gone_streak INTEGER NOT NULL DEFAULT 0 CHECK (gone_streak >= 0);
