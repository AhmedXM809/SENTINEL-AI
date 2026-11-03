-- SENTINEL AI migration 005
-- TOTP MFA enrollment, encrypted secrets, recovery codes and challenges.
--
-- This migration does not enable MFA for any existing user.
-- Existing users, passwords, roles, sessions and audit records are preserved.

BEGIN IMMEDIATE;

-- One MFA record per user.
-- enabled_at IS NULL means enrollment is pending.
-- setup_expires_at limits the lifetime of pending enrollment.
-- last_used_step prevents TOTP code replay.
CREATE TABLE user_mfa (
    user_id TEXT PRIMARY KEY NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    secret_ciphertext TEXT NOT NULL
        CHECK (length(secret_ciphertext) BETWEEN 80 AND 1024),

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    enabled_at TEXT,
    setup_expires_at TEXT,

    setup_failed_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (setup_failed_attempts BETWEEN 0 AND 5),

    last_used_step INTEGER
        CHECK (last_used_step IS NULL OR last_used_step >= 0),

    CHECK (
        (enabled_at IS NULL AND setup_expires_at IS NOT NULL)
        OR
        (enabled_at IS NOT NULL AND setup_expires_at IS NULL)
    )
);

-- Only hashes of high-entropy, single-use recovery codes are stored.
CREATE TABLE mfa_recovery_codes (
    id TEXT PRIMARY KEY NOT NULL,

    user_id TEXT NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    code_hash TEXT NOT NULL UNIQUE
        CHECK (
            length(code_hash) = 64
            AND code_hash NOT GLOB '*[^0-9a-f]*'
        ),

    created_at TEXT NOT NULL,
    used_at TEXT
);

CREATE INDEX idx_mfa_recovery_codes_user_used
ON mfa_recovery_codes(user_id, used_at);

-- Password verification creates a short-lived MFA challenge.
-- Store only the challenge token hash, never the raw token.
CREATE TABLE mfa_challenges (
    id TEXT PRIMARY KEY NOT NULL,

    user_id TEXT NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    token_hash TEXT NOT NULL UNIQUE
        CHECK (
            length(token_hash) = 64
            AND token_hash NOT GLOB '*[^0-9a-f]*'
        ),

    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,

    consumed_at TEXT,

    failed_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_attempts BETWEEN 0 AND 5),

    last_attempt_at TEXT
);

CREATE INDEX idx_mfa_challenges_user_expiry
ON mfa_challenges(user_id, expires_at);

PRAGMA user_version = 5;

COMMIT;