import secrets
import sqlite3
import unicodedata

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, FrozenSet

from app.db.connection import get_connection
from app.authentication.passwords import hash_password, verify_password
from app.authentication.sessions import (
    create_session,
    get_session_user,
    revoke_session,
)
from app.authentication.login_security import (
    LoginSecurityError,
    LoginThrottleStatus,
    check_login_throttle,
    clear_login_attempts,
    create_csrf_token,
    fingerprint_identifier,
    load_fingerprint_key,
    record_failed_login,
    verify_csrf_token,
)


class AuthenticationFailed(Exception):
    """Generic authentication failure."""


class LoginRateLimited(Exception):
    """Login attempt temporarily delayed."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__("Please wait before trying again.")


class AuthenticationConfigurationError(Exception):
    """Authentication configuration is unavailable."""


@dataclass(frozen=True)
class LoginResult:
    user_id: str
    username: str
    session_token: str
    csrf_token: str
    expires_at: str


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: str
    username: str
    roles: tuple[str, ...]
    permissions: FrozenSet[str]


_dummy_password_hash: str | None = None


def _get_dummy_password_hash() -> str:
    """Return a stable in-process hash for unknown-user verification."""

    global _dummy_password_hash

    if _dummy_password_hash is None:
        _dummy_password_hash = hash_password(
            secrets.token_urlsafe(32)
        )

    return _dummy_password_hash


def _normalized_username(username: str) -> str:
    if not isinstance(username, str):
        raise AuthenticationFailed("Invalid username or password.")

    normalized = unicodedata.normalize(
        "NFKC", username
    ).strip().casefold()

    if not normalized or len(normalized.encode("utf-8")) > 254:
        raise AuthenticationFailed("Invalid username or password.")

    return normalized


def _safe_password_candidate(password: str) -> str:
    """Bound password input before expensive hash verification."""

    if (
        not isinstance(password, str)
        or not password
        or len(password.encode("utf-8")) > 1024
    ):
        return "SENTINEL-invalid-password-input"

    return password


class LoginService:
    """Database-backed login, session and CSRF operations."""

    def __init__(
        self,
        connection_factory: Callable[[], AbstractContextManager] = get_connection,
        fingerprint_key: bytes | None = None,
    ):
        self._connection_factory = connection_factory
        self._fingerprint_key = fingerprint_key

        if fingerprint_key is not None and len(fingerprint_key) < 32:
            raise AuthenticationConfigurationError(
                "Fingerprint key must contain at least 32 bytes."
            )

    def _get_fingerprint_key(self) -> bytes:
        if self._fingerprint_key is not None:
            return self._fingerprint_key

        try:
            return load_fingerprint_key()
        except LoginSecurityError:
            raise AuthenticationConfigurationError(
                "Login security configuration is unavailable."
            ) from None

    def login(
        self,
        username: str,
        password: str,
    ) -> LoginResult:
        """Authenticate a user and create a session plus CSRF token."""

        normalized = _normalized_username(username)

        try:
            identifier_hash = fingerprint_identifier(
                normalized,
                self._get_fingerprint_key(),
            )
        except LoginSecurityError:
            raise AuthenticationFailed(
                "Invalid username or password."
            ) from None

        candidate = _safe_password_candidate(password)

        # Check the existing throttle before attempting expensive hashing.
        with self._connection_factory() as connection:
            throttle = check_login_throttle(
                connection,
                identifier_hash,
            )

            user = connection.execute(
                """
                SELECT id, username, password_hash, is_active
                FROM users
                WHERE username = ? COLLATE NOCASE
                LIMIT 1
                """,
                (normalized,),
            ).fetchone()

        if not throttle.allowed:
            raise LoginRateLimited(throttle.retry_after_seconds)

        # Unknown users receive an Argon2 verification too, reducing
        # differences in response behavior that could reveal account names.
        stored_hash = (
            user["password_hash"]
            if user is not None
            else _get_dummy_password_hash()
        )

        try:
            password_matches = verify_password(
                candidate,
                stored_hash,
            )
        except (ValueError, TypeError):
            password_matches = False

        if (
            user is None
            or user["is_active"] != 1
            or not password_matches
            or candidate != password
        ):
            with self._connection_factory() as connection:
                record_failed_login(
                    connection,
                    identifier_hash,
                    user_id=user["id"] if user is not None else None,
                )

            raise AuthenticationFailed(
                "Invalid username or password."
            )

        # Recheck throttling and account state inside a write transaction.
        # This avoids issuing a session if another request has already
        # exhausted the identifier's retry allowance.
        result = None
        inactive = False

        with self._connection_factory() as connection:
            connection.execute("BEGIN IMMEDIATE")

            latest = check_login_throttle(
                connection,
                identifier_hash,
            )

            if not latest.allowed:
                raise LoginRateLimited(latest.retry_after_seconds)

            current_user = connection.execute(
                """
                SELECT id, username, is_active
                FROM users
                WHERE id = ?
                """,
                (user["id"],),
            ).fetchone()

            if current_user is None or current_user["is_active"] != 1:
                record_failed_login(
                    connection,
                    identifier_hash,
                    user_id=user["id"],
                )
                inactive = True
            else:
                session_token, expires_at = create_session(
                    connection,
                    user_id=user["id"],
                )

                csrf_token = create_csrf_token(
                    connection,
                    session_token,
                )

                clear_login_attempts(
                    connection,
                    identifier_hash,
                )

                timestamp = (
                    datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )

                connection.execute(
                    """
                    INSERT INTO audit_log (
                        id, user_id, action, resource_type,
                        resource_id, outcome, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        secrets.token_hex(16),
                        user["id"],
                        "auth.login.success",
                        "session",
                        None,
                        "success",
                        timestamp,
                    ),
                )

                result = LoginResult(
                    user_id=user["id"],
                    username=current_user["username"],
                    session_token=session_token,
                    csrf_token=csrf_token,
                    expires_at=expires_at,
                )

        if inactive or result is None:
            raise AuthenticationFailed(
                "Invalid username or password."
            )

        return result

    def get_current_user(
        self,
        session_token: str,
    ) -> AuthenticatedUser | None:
        """Validate a session and load its server-side permissions."""

        with self._connection_factory() as connection:
            user_id = get_session_user(
                connection,
                session_token,
            )

            if user_id is None:
                return None

            user = connection.execute(
                """
                SELECT id, username
                FROM users
                WHERE id = ? AND is_active = 1
                """,
                (user_id,),
            ).fetchone()

            if user is None:
                return None

            roles = connection.execute(
                """
                SELECT r.name
                FROM user_roles ur
                JOIN roles r ON r.id = ur.role_id
                WHERE ur.user_id = ?
                ORDER BY r.name
                """,
                (user_id,),
            ).fetchall()

            permissions = connection.execute(
                """
                SELECT DISTINCT p.name
                FROM user_roles ur
                JOIN role_permissions rp ON rp.role_id = ur.role_id
                JOIN permissions p ON p.id = rp.permission_id
                WHERE ur.user_id = ?
                ORDER BY p.name
                """,
                (user_id,),
            ).fetchall()

            return AuthenticatedUser(
                user_id=user["id"],
                username=user["username"],
                roles=tuple(row["name"] for row in roles),
                permissions=frozenset(
                    row["name"] for row in permissions
                ),
            )

    def issue_csrf_token(self, session_token: str) -> str:
        """Issue a CSRF token for an active session."""

        with self._connection_factory() as connection:
            return create_csrf_token(connection, session_token)

    def validate_csrf(
        self,
        session_token: str,
        csrf_token: str,
    ) -> bool:
        with self._connection_factory() as connection:
            return verify_csrf_token(
                connection,
                session_token,
                csrf_token,
            )

    def logout(self, session_token: str) -> bool:
        """Revoke a session and audit authenticated logout."""

        with self._connection_factory() as connection:
            user_id = get_session_user(
                connection,
                session_token,
            )

            revoked = revoke_session(
                connection,
                session_token,
            )

            if revoked and user_id:
                timestamp = (
                    datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )

                connection.execute(
                    """
                    INSERT INTO audit_log (
                        id, user_id, action, resource_type,
                        resource_id, outcome, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        secrets.token_hex(16),
                        user_id,
                        "auth.logout",
                        "session",
                        None,
                        "success",
                        timestamp,
                    ),
                )

            return revoked