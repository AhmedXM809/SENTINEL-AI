import hashlib
import secrets
import sqlite3

from datetime import datetime, timedelta, timezone
from uuid import uuid4


SESSION_LIFETIME_MINUTES = 30
MAX_TOKEN_LENGTH = 256


class SessionError(ValueError):
    """Raised when session creation requirements are not met."""


def _utc_timestamp(value: datetime | None = None) -> str:
    """Return a consistently formatted UTC timestamp."""
    if value is None:
        value = datetime.now(timezone.utc)

    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _hash_session_token(token: str) -> str | None:
    """Return a SHA-256 verifier for a valid session token."""

    if not isinstance(token, str) or not token:
        return None

    try:
        encoded = token.encode("utf-8")
    except UnicodeEncodeError:
        return None

    if len(encoded) > MAX_TOKEN_LENGTH:
        return None

    return hashlib.sha256(encoded).hexdigest()


def create_session(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    lifetime_minutes: int = SESSION_LIFETIME_MINUTES,
) -> tuple[str, str]:
    """Create a session and return its raw token and expiry.

    Only the SHA-256 token hash is stored in SQLite.
    The caller is responsible for committing the transaction.
    """

    if not isinstance(lifetime_minutes, int) or isinstance(
        lifetime_minutes, bool
    ):
        raise SessionError("Session lifetime must be an integer.")

    if not 1 <= lifetime_minutes <= 480:
        raise SessionError("Session lifetime must be between 1 and 480 minutes.")

    user = connection.execute(
        "SELECT is_active FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if user is None or user["is_active"] != 1:
        raise SessionError("An active user is required.")

    # 32 random bytes provide 256 bits of token entropy.
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_session_token(raw_token)

    now = datetime.now(timezone.utc)
    created_at = _utc_timestamp(now)
    expires_at = _utc_timestamp(
        now + timedelta(minutes=lifetime_minutes)
    )

    connection.execute(
        """
        INSERT INTO user_sessions (
            id, user_id, token_hash, created_at, expires_at, revoked_at
        )
        VALUES (?, ?, ?, ?, ?, NULL)
        """,
        (
            str(uuid4()),
            user_id,
            token_hash,
            created_at,
            expires_at,
        ),
    )

    # Raw token is returned exactly once. Never log or persist it.
    return raw_token, expires_at


def get_session_user(
    connection: sqlite3.Connection,
    raw_token: str,
) -> str | None:
    """Return the active user's ID for a valid, unexpired session."""

    token_hash = _hash_session_token(raw_token)

    if token_hash is None:
        return None

    now = _utc_timestamp()

    row = connection.execute(
        """
        SELECT s.user_id
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
          AND s.revoked_at IS NULL
          AND s.expires_at > ?
          AND u.is_active = 1
        LIMIT 1
        """,
        (token_hash, now),
    ).fetchone()

    return row["user_id"] if row else None


def revoke_session(
    connection: sqlite3.Connection,
    raw_token: str,
) -> bool:
    """Revoke a session. Repeated revocation is harmless."""

    token_hash = _hash_session_token(raw_token)

    if token_hash is None:
        return False

    revoked_at = _utc_timestamp()

    cursor = connection.execute(
        """
        UPDATE user_sessions
        SET revoked_at = ?
        WHERE token_hash = ?
          AND revoked_at IS NULL
        """,
        (revoked_at, token_hash),
    )

    return cursor.rowcount == 1


def revoke_user_sessions(
    connection: sqlite3.Connection,
    user_id: str,
) -> int:
    """Revoke every active session belonging to a user."""

    revoked_at = _utc_timestamp()

    cursor = connection.execute(
        """
        UPDATE user_sessions
        SET revoked_at = ?
        WHERE user_id = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        """,
        (revoked_at, user_id, revoked_at),
    )

    return cursor.rowcount