-- SENTINEL AI migration 003
-- CSRF protection and persistent login throttling.

ALTER TABLE user_sessions
ADD COLUMN csrf_token_hash TEXT;

-- Revoke pre-migration sessions so they must authenticate again.
UPDATE user_sessions
SET revoked_at = COALESCE(
    revoked_at,
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
)
WHERE revoked_at IS NULL;

CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    attempted_at TEXT NOT NULL
);

-- Known users are throttled independently.
CREATE INDEX idx_login_attempts_user_time
ON login_attempts(user_id, attempted_at);

-- Unknown usernames share an aggregate throttle bucket.
CREATE INDEX idx_login_attempts_time
ON login_attempts(attempted_at);

PRAGMA user_version = 3;