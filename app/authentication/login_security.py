import hashlib
import hmac
import math
import os
import re
import secrets
import sqlite3
import unicodedata

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.authentication.sessions import SESSION_IDLE_TIMEOUT_MINUTES

FINGERPRINT_ENV_NAME = "SENTINEL_LOGIN_FINGERPRINT_KEY"
FINGERPRINT_KEY_BYTES = 32

LOGIN_WINDOW_MINUTES = 15
LOGIN_BACKOFF_SECONDS = (1, 2, 4, 8, 16, 30)
MAX_TOKEN_LENGTH = 256

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class LoginSecurityError(ValueError):
    """Raised when login-security input or configuration is invalid."""


@dataclass(frozen=True)
class LoginThrottleStatus:
    failures_in_window: int
    retry_after_seconds: int

    @property
    def allowed(self) -> bool:
        return self.retry_after_seconds == 0


def _utc_timestamp(value: datetime | None = None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)

    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_fingerprint(identifier_hash: str) -> None:
    if (
        not isinstance(identifier_hash, str)
        or not _HEX_64.fullmatch(identifier_hash)
    ):
        raise LoginSecurityError("Invalid identifier fingerprint.")


def load_fingerprint_key() -> bytes:
    """Load the stable 32-byte HMAC key from the process environment."""

    value = os.environ.get(FINGERPRINT_ENV_NAME)

    if not value:
        raise LoginSecurityError(
            f"{FINGERPRINT_ENV_NAME} is not configured."
        )

    try:
        key = bytes.fromhex(value)
    except ValueError:
        raise LoginSecurityError(
            "The login fingerprint key has an invalid format."
        ) from None

    if len(key) != FINGERPRINT_KEY_BYTES:
        raise LoginSecurityError(
            "The login fingerprint key must contain exactly 32 bytes."
        )

    return key


def fingerprint_identifier(
    identifier: str,
    secret_key: bytes,
) -> str:
    """Create a keyed fingerprint without storing the raw identifier."""

    if not isinstance(identifier, str):
        raise LoginSecurityError("Login identifier must be text.")

    normalized = unicodedata.normalize("NFKC", identifier).strip().casefold()

    if not normalized:
        raise LoginSecurityError("Login identifier must not be empty.")

    if len(normalized.encode("utf-8")) > 254:
        raise LoginSecurityError("Login identifier is too long.")

    if not isinstance(secret_key, bytes) or len(secret_key) < 32:
        raise LoginSecurityError(
            "A fingerprint key of at least 32 bytes is required."
        )

    message = b"sentinel-login-identifier:v1\x00" + normalized.encode("utf-8")

    return hmac.new(
        secret_key,
        message,
        hashlib.sha256,
    ).hexdigest()


def check_login_throttle(
    connection: sqlite3.Connection,
    identifier_hash: str,
    *,
    now: datetime | None = None,
) -> LoginThrottleStatus:
    """Calculate the current delay using failures from the last 15 minutes."""

    _validate_fingerprint(identifier_hash)

    current_time = now or datetime.now(timezone.utc)
    current_time = current_time.astimezone(timezone.utc)

    cutoff = _utc_timestamp(
        current_time - timedelta(minutes=LOGIN_WINDOW_MINUTES)
    )

    rows = connection.execute(
        """
        SELECT attempted_at
        FROM login_attempts
        WHERE identifier_hash = ?
          AND attempted_at > ?
        ORDER BY attempted_at DESC
        """,
        (identifier_hash, cutoff),
    ).fetchall()

    failure_count = len(rows)

    if failure_count == 0:
        return LoginThrottleStatus(0, 0)

    last_attempt = _parse_timestamp(rows[0]["attempted_at"])
    elapsed = max(
        0.0,
        (current_time - last_attempt).total_seconds(),
    )

    delay = LOGIN_BACKOFF_SECONDS[
        min(failure_count - 1, len(LOGIN_BACKOFF_SECONDS) - 1)
    ]

    retry_after = max(0, math.ceil(delay - elapsed))

    return LoginThrottleStatus(
        failures_in_window=failure_count,
        retry_after_seconds=retry_after,
    )


def record_failed_login(
    connection: sqlite3.Connection,
    identifier_hash: str,
    *,
    user_id: str | None = None,
    now: datetime | None = None,
) -> None:
    """Record a failed attempt without storing a raw username or password."""

    _validate_fingerprint(identifier_hash)

    connection.execute(
        """
        INSERT INTO login_attempts (
            user_id,
            attempted_at,
            identifier_hash
        )
        VALUES (?, ?, ?)
        """,
        (
            user_id,
            _utc_timestamp(now),
            identifier_hash,
        ),
    )


def clear_login_attempts(
    connection: sqlite3.Connection,
    identifier_hash: str,
) -> int:
    """Remove failed attempts after successful authentication."""

    _validate_fingerprint(identifier_hash)

    cursor = connection.execute(
        "DELETE FROM login_attempts WHERE identifier_hash = ?",
        (identifier_hash,),
    )

    return cursor.rowcount


def prune_old_login_attempts(
    connection: sqlite3.Connection,
    *,
    now: datetime | None = None,
) -> int:
    """Remove records outside the rolling observation window."""

    current_time = now or datetime.now(timezone.utc)

    cutoff = _utc_timestamp(
        current_time - timedelta(minutes=LOGIN_WINDOW_MINUTES)
    )

    cursor = connection.execute(
        "DELETE FROM login_attempts WHERE attempted_at <= ?",
        (cutoff,),
    )

    return cursor.rowcount


def _token_hash(token: str) -> str | None:
    if not isinstance(token, str) or not token:
        return None

    try:
        encoded = token.encode("utf-8")
    except UnicodeEncodeError:
        return None

    if len(encoded) > MAX_TOKEN_LENGTH:
        return None

    return hashlib.sha256(encoded).hexdigest()


def create_csrf_token(
    connection: sqlite3.Connection,
    session_token: str,
) -> str:
    """Generate a CSRF token and persist only its SHA-256 hash."""

    session_hash = _token_hash(session_token)

    if session_hash is None:
        raise LoginSecurityError("Invalid session token.")

    now_datetime = datetime.now(timezone.utc)
    now = _utc_timestamp(now_datetime)

    idle_cutoff = _utc_timestamp(
        now_datetime - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
    )

    session = connection.execute(
        """
        SELECT s.id
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
          AND s.revoked_at IS NULL
          AND s.expires_at > ?
          AND s.last_seen_at > ?
          AND u.is_active = 1
        LIMIT 1
        """,
        (session_hash, now, idle_cutoff),
    ).fetchone()

    if session is None:
        raise LoginSecurityError("An active session is required.")

    raw_csrf_token = secrets.token_urlsafe(32)
    csrf_hash = _token_hash(raw_csrf_token)

    cursor = connection.execute(
        """
        UPDATE user_sessions
        SET csrf_token_hash = ?
        WHERE id = ?
          AND revoked_at IS NULL
        """,
        (csrf_hash, session["id"]),
    )

    if cursor.rowcount != 1:
        raise LoginSecurityError("CSRF token creation failed.")

    return raw_csrf_token


def verify_csrf_token(
    connection: sqlite3.Connection,
    session_token: str,
    csrf_token: str,
) -> bool:
    """Verify a CSRF token against a currently valid session."""

    session_hash = _token_hash(session_token)
    supplied_hash = _token_hash(csrf_token)

    if session_hash is None or supplied_hash is None:
        return False

    now_datetime = datetime.now(timezone.utc)
    now = _utc_timestamp(now_datetime)

    idle_cutoff = _utc_timestamp(
        now_datetime - timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
    )

    row = connection.execute(
        """
        SELECT s.csrf_token_hash
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
          AND s.revoked_at IS NULL
          AND s.expires_at > ?
          AND s.last_seen_at > ?
          AND u.is_active = 1
        LIMIT 1
        """,
        (session_hash, now, idle_cutoff),
    ).fetchone()

    stored_hash = row["csrf_token_hash"] if row else None

    # Always perform a constant-time comparison.
    candidate = stored_hash if stored_hash else ("0" * 64)
    matches = secrets.compare_digest(candidate, supplied_hash)

    return bool(row and stored_hash and matches)