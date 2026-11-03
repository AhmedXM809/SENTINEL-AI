import hashlib
import secrets
import sqlite3

from datetime import datetime, timedelta, timezone
from uuid import uuid4

SESSION_LIFETIME_MINUTES = 30
SESSION_IDLE_TIMEOUT_MINUTES = 15
MAX_TOKEN_LENGTH = 256


class SessionError(ValueError):
    """Raised when session creation requirements are not met."""


def _utc_timestamp(value: datetime | None = None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)

    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _hash_session_token(token: str) -> str | None:
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

    if (
        not isinstance(lifetime_minutes, int)
        or isinstance(lifetime_minutes, bool)
    ):
        raise SessionError("Session lifetime must be an integer.")

    if not 1 <= lifetime_minutes <= 480:
        raise SessionError("Invalid session lifetime.")

    user = connection.execute(
        "SELECT is_active FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if user is None or user["is_active"] != 1:
        raise SessionError("An active user is required.")

    token = secrets.token_urlsafe(32)
    token_hash = _hash_session_token(token)

    now = datetime.now(timezone.utc)
    created_at = _utc_timestamp(now)
    expires_at = _utc_timestamp(
        now + timedelta(minutes=lifetime_minutes)
    )

    connection.execute(
        """
        INSERT INTO user_sessions (
            id, user_id, token_hash, created_at,
            expires_at, revoked_at, last_seen_at
        )
        VALUES (?, ?, ?, ?, ?, NULL, ?)
        """,
        (
            str(uuid4()),
            user_id,
            token_hash,
            created_at,
            expires_at,
            created_at,
        ),
    )

    return token, expires_at


def get_session_user(
    connection: sqlite3.Connection,
    raw_token: str,
) -> str | None:
    """Validate a session and atomically refresh its idle timestamp."""

    token_hash = _hash_session_token(raw_token)

    if token_hash is None:
        return None

    now_datetime = datetime.now(timezone.utc)
    now = _utc_timestamp(now_datetime)

    idle_cutoff = _utc_timestamp(
        now_datetime - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
    )

    cursor = connection.execute(
        """
        UPDATE user_sessions
        SET last_seen_at = ?
        WHERE token_hash = ?
          AND revoked_at IS NULL
          AND expires_at > ?
          AND last_seen_at > ?
          AND EXISTS (
              SELECT 1
              FROM users u
              WHERE u.id = user_sessions.user_id
                AND u.is_active = 1
          )
        """,
        (now, token_hash, now, idle_cutoff),
    )

    if cursor.rowcount != 1:
        return None

    row = connection.execute(
        """
        SELECT user_id
        FROM user_sessions
        WHERE token_hash = ?
          AND revoked_at IS NULL
        """,
        (token_hash,),
    ).fetchone()

    return row["user_id"] if row else None


def revoke_session(
    connection: sqlite3.Connection,
    raw_token: str,
) -> bool:

    token_hash = _hash_session_token(raw_token)

    if token_hash is None:
        return False

    cursor = connection.execute(
        """
        UPDATE user_sessions
        SET revoked_at = ?
        WHERE token_hash = ?
          AND revoked_at IS NULL
        """,
        (_utc_timestamp(), token_hash),
    )

    return cursor.rowcount == 1


def revoke_user_sessions(
    connection: sqlite3.Connection,
    user_id: str,
) -> int:
    """Revoke only currently active, non-expired user sessions."""

    now_datetime = datetime.now(timezone.utc)
    now = _utc_timestamp(now_datetime)

    idle_cutoff = _utc_timestamp(
        now_datetime - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
    )

    cursor = connection.execute(
        """
        UPDATE user_sessions
        SET revoked_at = ?
        WHERE user_id = ?
          AND revoked_at IS NULL
          AND expires_at > ?
          AND last_seen_at > ?
        """,
        (now, user_id, now, idle_cutoff),
    )

    return cursor.rowcount