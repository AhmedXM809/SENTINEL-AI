-- SENTINEL AI migration 004
-- Per-identifier persistent login throttling.
-- Store a username fingerprint, not the raw submitted username.

ALTER TABLE login_attempts
ADD COLUMN identifier_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_login_attempts_identifier_time
ON login_attempts(identifier_hash, attempted_at);

PRAGMA user_version = 4;