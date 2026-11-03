-- SENTINEL AI migration 002
-- Adds last activity tracking for session idle expiration.

ALTER TABLE user_sessions
ADD COLUMN last_seen_at TEXT NOT NULL
DEFAULT '1970-01-01T00:00:00Z';

-- Preserve existing sessions by using their original creation time.
UPDATE user_sessions
SET last_seen_at = created_at;

CREATE INDEX idx_user_sessions_last_seen
ON user_sessions(last_seen_at);

PRAGMA user_version = 2;