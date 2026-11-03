import hashlib
import re
import secrets
import sqlite3

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from app.db.connection import get_connection
from app.authentication.sessions import (
    create_session,
    get_session_user,
    revoke_user_sessions,
)
from app.authentication.login_security import (
    LoginSecurityError,
    check_login_throttle,
    clear_login_attempts,
    create_csrf_token,
    fingerprint_identifier,
    load_fingerprint_key,
    record_failed_login,
)
from app.authentication.mfa import (
    MFAConfigurationError,
    MFAInputError,
    create_otpauth_uri,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    normalize_recovery_code,
    verify_totp_code,
)


MFA_SETUP_LIFETIME_MINUTES = 10
MFA_CHALLENGE_LIFETIME_SECONDS = 300
MFA_MAX_CHALLENGE_FAILURES = 5
MFA_MAX_ENROLLMENT_FAILURES = 5

_RECOVERY_FORMAT = re.compile(r"^[A-Fa-f0-9]{32}$")


class MFAFlowAuthenticationFailed(Exception):
    """Generic MFA authentication failure."""


class MFAFlowConfigurationError(Exception):
    """MFA encryption or configuration failure."""


class MFAFlowRateLimited(Exception):
    """MFA verification temporarily rate limited."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__("MFA verification is temporarily delayed.")


class MFAEnrollmentConflict(Exception):
    """MFA is already enabled or enrollment cannot be started."""


class MFAEnrollmentFailed(Exception):
    """MFA enrollment could not be completed."""


@dataclass(frozen=True)
class MFAEnrollmentResult:
    secret: str
    provisioning_uri: str
    expires_at: str


@dataclass(frozen=True)
class MFAChallengeResult:
    challenge_token: str
    expires_at: str


@dataclass(frozen=True)
class MFACompletedLogin:
    user_id: str
    username: str
    session_token: str
    csrf_token: str
    expires_at: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime | None = None) -> str:
    current = value or _utc_now()

    return (
        current.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _hash_challenge_token(token: str) -> str | None:
    if not isinstance(token, str) or not token:
        return None

    try:
        encoded = token.encode("utf-8")
    except UnicodeEncodeError:
        return None

    if len(encoded) > 256:
        return None

    return hashlib.sha256(encoded).hexdigest()


class MFAService:
    """Database-backed MFA enrollment and two-factor authentication."""

    def __init__(
        self,
        connection_factory: Callable[[], AbstractContextManager] = get_connection,
        fingerprint_key: bytes | None = None,
    ):
        self._connection_factory = connection_factory
        self._fingerprint_key = fingerprint_key

        if fingerprint_key is not None and len(fingerprint_key) < 32:
            raise MFAFlowConfigurationError(
                "Login fingerprint key must contain at least 32 bytes."
            )

    def _get_fingerprint_key(self) -> bytes:
        if self._fingerprint_key is not None:
            return self._fingerprint_key

        try:
            return load_fingerprint_key()
        except LoginSecurityError:
            raise MFAFlowConfigurationError(
                "Login security configuration is unavailable."
            ) from None

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str | None,
        outcome: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO audit_log (
                id, user_id, action, resource_type,
                resource_id, outcome, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                user_id,
                action,
                resource_type,
                resource_id,
                outcome,
                _timestamp(),
            ),
        )

    @staticmethod
    def is_enabled(
        connection: sqlite3.Connection,
        user_id: str,
    ) -> bool:
        row = connection.execute(
            """
            SELECT 1
            FROM user_mfa
            WHERE user_id = ?
              AND enabled_at IS NOT NULL
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

        return row is not None

    def create_challenge(
        self,
        connection: sqlite3.Connection,
        user_id: str,
    ) -> MFAChallengeResult:
        """Create a short-lived challenge after successful password verification.

        The caller owns the surrounding database transaction.
        """

        enabled = self.is_enabled(connection, user_id)

        if not enabled:
            raise MFAEnrollmentFailed(
                "An enabled MFA configuration is required."
            )

        now = _utc_now()
        created_at = _timestamp(now)
        expires_at = _timestamp(
            now + timedelta(seconds=MFA_CHALLENGE_LIFETIME_SECONDS)
        )

        # A new challenge invalidates any previous unused challenge
        # for this user.
        connection.execute(
            """
            UPDATE mfa_challenges
            SET consumed_at = ?
            WHERE user_id = ?
              AND consumed_at IS NULL
            """,
            (created_at, user_id),
        )

        raw_token = secrets.token_urlsafe(32)
        token_hash = _hash_challenge_token(raw_token)

        if token_hash is None:
            raise MFAFlowConfigurationError(
                "MFA challenge token generation failed."
            )

        challenge_id = str(uuid4())

        connection.execute(
            """
            INSERT INTO mfa_challenges (
                id, user_id, token_hash,
                created_at, expires_at, consumed_at,
                failed_attempts, last_attempt_at
            )
            VALUES (?, ?, ?, ?, ?, NULL, 0, NULL)
            """,
            (
                challenge_id,
                user_id,
                token_hash,
                created_at,
                expires_at,
            ),
        )

        self._audit(
            connection,
            user_id=user_id,
            action="auth.login.mfa_challenge",
            resource_type="mfa_challenge",
            resource_id=challenge_id,
            outcome="pending",
        )

        return MFAChallengeResult(
            challenge_token=raw_token,
            expires_at=expires_at,
        )

    def start_enrollment(
        self,
        session_token: str,
    ) -> MFAEnrollmentResult:
        """Start or replace an unconfirmed enrollment for the active user."""

        secret = generate_totp_secret()

        try:
            ciphertext = encrypt_totp_secret(secret)
        except MFAConfigurationError:
            raise MFAFlowConfigurationError(
                "MFA encryption is unavailable."
            ) from None

        now = _utc_now()
        created_at = _timestamp(now)
        expires_at = _timestamp(
            now + timedelta(minutes=MFA_SETUP_LIFETIME_MINUTES)
        )

        with self._connection_factory() as connection:
            connection.execute("BEGIN IMMEDIATE")

            user_id = get_session_user(
                connection,
                session_token,
            )

            if user_id is None:
                raise MFAFlowAuthenticationFailed(
                    "An active authenticated session is required."
                )

            existing = connection.execute(
                """
                SELECT enabled_at
                FROM user_mfa
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            if existing is not None and existing["enabled_at"] is not None:
                raise MFAEnrollmentConflict(
                    "MFA is already enabled."
                )

            # Replace any prior unconfirmed enrollment. Existing enabled
            # MFA can never be overwritten through this method.
            connection.execute(
                "DELETE FROM user_mfa WHERE user_id = ?",
                (user_id,),
            )

            connection.execute(
                """
                INSERT INTO user_mfa (
                    user_id, secret_ciphertext, created_at,
                    updated_at, enabled_at, setup_expires_at,
                    setup_failed_attempts, last_used_step
                )
                VALUES (?, ?, ?, ?, NULL, ?, 0, NULL)
                """,
                (
                    user_id,
                    ciphertext,
                    created_at,
                    created_at,
                    expires_at,
                ),
            )

            self._audit(
                connection,
                user_id=user_id,
                action="auth.mfa.enrollment.started",
                resource_type="user_mfa",
                resource_id=user_id,
                outcome="success",
            )

            user = connection.execute(
                "SELECT username FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

            if user is None:
                raise MFAFlowAuthenticationFailed(
                    "Active user not found."
                )

        provisioning_uri = create_otpauth_uri(
            secret,
            user["username"],
        )

        # The plaintext secret is returned once to the authenticated
        # enrollment client. Only ciphertext is persisted.
        return MFAEnrollmentResult(
            secret=secret,
            provisioning_uri=provisioning_uri,
            expires_at=expires_at,
        )

    def confirm_enrollment(
        self,
        session_token: str,
        code: str,
    ) -> tuple[str, ...]:
        """Confirm TOTP and create ten one-time recovery codes."""

        recovery_codes: list[str] | None = None
        failure: str | None = None

        with self._connection_factory() as connection:
            connection.execute("BEGIN IMMEDIATE")

            user_id = get_session_user(
                connection,
                session_token,
            )

            if user_id is None:
                raise MFAFlowAuthenticationFailed(
                    "An active authenticated session is required."
                )

            enrollment = connection.execute(
                """
                SELECT secret_ciphertext, setup_expires_at,
                       setup_failed_attempts, enabled_at
                FROM user_mfa
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            if enrollment is None or enrollment["enabled_at"] is not None:
                raise MFAEnrollmentFailed(
                    "No pending MFA enrollment was found."
                )

            now = _utc_now()
            timestamp = _timestamp(now)

            if (
                not enrollment["setup_expires_at"]
                or enrollment["setup_expires_at"] <= timestamp
            ):
                connection.execute(
                    "DELETE FROM user_mfa WHERE user_id = ?",
                    (user_id,),
                )

                self._audit(
                    connection,
                    user_id=user_id,
                    action="auth.mfa.enrollment.expired",
                    resource_type="user_mfa",
                    resource_id=user_id,
                    outcome="failure",
                )

                failure = "MFA enrollment expired."

            elif enrollment["setup_failed_attempts"] >= MFA_MAX_ENROLLMENT_FAILURES:
                failure = "MFA enrollment attempt limit reached."

            else:
                try:
                    secret = decrypt_totp_secret(
                        enrollment["secret_ciphertext"]
                    )
                except MFAConfigurationError:
                    raise MFAFlowConfigurationError(
                        "Stored MFA secret could not be decrypted."
                    ) from None

                try:
                    accepted_step = verify_totp_code(
                        secret,
                        code,
                        last_used_step=None,
                    )
                except MFAInputError:
                    accepted_step = None

                if accepted_step is None:
                    attempts = enrollment["setup_failed_attempts"] + 1

                    if attempts >= MFA_MAX_ENROLLMENT_FAILURES:
                        connection.execute(
                            "DELETE FROM user_mfa WHERE user_id = ?",
                            (user_id,),
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE user_mfa
                            SET setup_failed_attempts = ?,
                                updated_at = ?
                            WHERE user_id = ?
                              AND enabled_at IS NULL
                            """,
                            (attempts, timestamp, user_id),
                        )

                    self._audit(
                        connection,
                        user_id=user_id,
                        action="auth.mfa.enrollment.confirmation",
                        resource_type="user_mfa",
                        resource_id=user_id,
                        outcome="failure",
                    )

                    failure = "MFA enrollment confirmation failed."

                else:
                    connection.execute(
                        """
                        UPDATE user_mfa
                        SET enabled_at = ?,
                            setup_expires_at = NULL,
                            setup_failed_attempts = 0,
                            last_used_step = ?,
                            updated_at = ?
                        WHERE user_id = ?
                          AND enabled_at IS NULL
                        """,
                        (
                            timestamp,
                            accepted_step,
                            timestamp,
                            user_id,
                        ),
                    )

                    # Enabling MFA invalidates every existing active session.
                    # This prevents an older password-only session from
                    # remaining authenticated after MFA activation.
                    revoked_count = revoke_user_sessions(
                        connection,
                        user_id,
                    )

                    if revoked_count:
                        self._audit(
                            connection,
                            user_id=user_id,
                            action="auth.mfa.sessions_revoked",
                            resource_type="user_sessions",
                            resource_id=user_id,
                            outcome="success",
                        )

                    recovery_codes = generate_recovery_codes()

                    for recovery_code in recovery_codes:
                        connection.execute(
                            """
                            INSERT INTO mfa_recovery_codes (
                                id, user_id, code_hash, created_at, used_at
                            )
                            VALUES (?, ?, ?, ?, NULL)
                            """,
                            (
                                str(uuid4()),
                                user_id,
                                hash_recovery_code(recovery_code),
                                timestamp,
                            ),
                        )

                    self._audit(
                        connection,
                        user_id=user_id,
                        action="auth.mfa.enabled",
                        resource_type="user_mfa",
                        resource_id=user_id,
                        outcome="success",
                    )

        if failure is not None:
            raise MFAEnrollmentFailed(failure)

        if recovery_codes is None:
            raise MFAEnrollmentFailed(
                "MFA enrollment could not be completed."
            )

        # These plaintext codes are returned only once.
        return tuple(recovery_codes)

    def complete_challenge(
        self,
        challenge_token: str,
        code: str,
    ) -> MFACompletedLogin:
        """Verify TOTP or consume a recovery code, then issue a session."""

        challenge_hash = _hash_challenge_token(challenge_token)

        if challenge_hash is None:
            raise MFAFlowAuthenticationFailed(
                "Invalid MFA challenge."
            )

        if not isinstance(code, str) or not 1 <= len(code) <= 64:
            raise MFAFlowAuthenticationFailed(
                "Invalid MFA verification code."
            )

        failure = False
        result: MFACompletedLogin | None = None
        rate_limited: int | None = None

        with self._connection_factory() as connection:
            connection.execute("BEGIN IMMEDIATE")

            challenge = connection.execute(
                """
                SELECT
                    c.id AS challenge_id,
                    c.user_id,
                    c.expires_at,
                    c.consumed_at,
                    c.failed_attempts,
                    u.username,
                    u.is_active,
                    m.secret_ciphertext,
                    m.last_used_step
                FROM mfa_challenges c
                JOIN users u ON u.id = c.user_id
                JOIN user_mfa m ON m.user_id = c.user_id
                WHERE c.token_hash = ?
                  AND m.enabled_at IS NOT NULL
                LIMIT 1
                """,
                (challenge_hash,),
            ).fetchone()

            if (
                challenge is None
                or challenge["is_active"] != 1
                or challenge["consumed_at"] is not None
                or challenge["failed_attempts"] >= MFA_MAX_CHALLENGE_FAILURES
                or challenge["expires_at"] <= _timestamp()
            ):
                raise MFAFlowAuthenticationFailed(
                    "Invalid or expired MFA challenge."
                )

            try:
                identifier_hash = fingerprint_identifier(
                    challenge["username"],
                    self._get_fingerprint_key(),
                )
            except LoginSecurityError:
                raise MFAFlowConfigurationError(
                    "Login security configuration is unavailable."
                ) from None

            throttle = check_login_throttle(
                connection,
                identifier_hash,
            )

            if not throttle.allowed:
                rate_limited = throttle.retry_after_seconds
            else:
                now = _timestamp()
                accepted_step: int | None = None
                recovery_record_id: str | None = None

                if re.fullmatch(r"^[0-9]{6}$", code):
                    try:
                        secret = decrypt_totp_secret(
                            challenge["secret_ciphertext"]
                        )

                        accepted_step = verify_totp_code(
                            secret,
                            code,
                            last_used_step=challenge["last_used_step"],
                        )

                    except MFAConfigurationError:
                        raise MFAFlowConfigurationError(
                            "MFA encryption is unavailable."
                        ) from None

                    except MFAInputError:
                        accepted_step = None

                else:
                    try:
                        normalized = normalize_recovery_code(code)
                        recovery_hash = hash_recovery_code(normalized)

                        recovery = connection.execute(
                            """
                            SELECT id
                            FROM mfa_recovery_codes
                            WHERE user_id = ?
                              AND code_hash = ?
                              AND used_at IS NULL
                            LIMIT 1
                            """,
                            (
                                challenge["user_id"],
                                recovery_hash,
                            ),
                        ).fetchone()

                        if recovery is not None:
                            recovery_record_id = recovery["id"]

                    except MFAInputError:
                        recovery_record_id = None

                valid_factor = (
                    accepted_step is not None
                    or recovery_record_id is not None
                )

                if not valid_factor:
                    attempts = challenge["failed_attempts"] + 1

                    connection.execute(
                        """
                        UPDATE mfa_challenges
                        SET failed_attempts = ?,
                            last_attempt_at = ?,
                            consumed_at = CASE
                                WHEN ? >= ?
                                THEN ?
                                ELSE consumed_at
                            END
                        WHERE id = ?
                          AND consumed_at IS NULL
                        """,
                        (
                            attempts,
                            now,
                            attempts,
                            MFA_MAX_CHALLENGE_FAILURES,
                            now,
                            challenge["challenge_id"],
                        ),
                    )

                    record_failed_login(
                        connection,
                        identifier_hash,
                        user_id=challenge["user_id"],
                    )

                    self._audit(
                        connection,
                        user_id=challenge["user_id"],
                        action="auth.login.mfa.failure",
                        resource_type="mfa_challenge",
                        resource_id=challenge["challenge_id"],
                        outcome="failure",
                    )

                    failure = True

                else:
                    # The write transaction serializes MFA completion.
                    # A TOTP step or recovery code cannot be consumed twice.
                    if accepted_step is not None:
                        cursor = connection.execute(
                            """
                            UPDATE user_mfa
                            SET last_used_step = ?,
                                updated_at = ?
                            WHERE user_id = ?
                              AND (
                                  last_used_step IS NULL
                                  OR last_used_step < ?
                              )
                            """,
                            (
                                accepted_step,
                                now,
                                challenge["user_id"],
                                accepted_step,
                            ),
                        )

                        if cursor.rowcount != 1:
                            raise MFAFlowAuthenticationFailed(
                                "TOTP verification was already used."
                            )

                    else:
                        cursor = connection.execute(
                            """
                            UPDATE mfa_recovery_codes
                            SET used_at = ?
                            WHERE id = ?
                              AND user_id = ?
                              AND used_at IS NULL
                            """,
                            (
                                now,
                                recovery_record_id,
                                challenge["user_id"],
                            ),
                        )

                        if cursor.rowcount != 1:
                            raise MFAFlowAuthenticationFailed(
                                "Recovery code was already used."
                            )

                    cursor = connection.execute(
                        """
                        UPDATE mfa_challenges
                        SET consumed_at = ?
                        WHERE id = ?
                          AND consumed_at IS NULL
                        """,
                        (now, challenge["challenge_id"]),
                    )

                    if cursor.rowcount != 1:
                        raise MFAFlowAuthenticationFailed(
                            "MFA challenge has already been consumed."
                        )

                    session_token, expires_at = create_session(
                        connection,
                        user_id=challenge["user_id"],
                    )

                    csrf_token = create_csrf_token(
                        connection,
                        session_token,
                    )

                    clear_login_attempts(
                        connection,
                        identifier_hash,
                    )

                    self._audit(
                        connection,
                        user_id=challenge["user_id"],
                        action="auth.login.mfa.success",
                        resource_type="session",
                        resource_id=None,
                        outcome="success",
                    )

                    result = MFACompletedLogin(
                        user_id=challenge["user_id"],
                        username=challenge["username"],
                        session_token=session_token,
                        csrf_token=csrf_token,
                        expires_at=expires_at,
                    )

        if rate_limited is not None:
            raise MFAFlowRateLimited(rate_limited)

        if failure or result is None:
            raise MFAFlowAuthenticationFailed(
                "Invalid MFA verification code."
            )

        return result