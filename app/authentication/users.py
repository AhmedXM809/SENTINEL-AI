import re
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from pwdlib import PasswordHash

from app.authentication.passwords import hash_password

MIN_PASSWORD_LENGTH = 15
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")


class UserProvisioningError(ValueError):
    """Raised when user provisioning validation fails."""


class UserAlreadyExistsError(UserProvisioningError):
    """Raised when a username or email is already registered."""


def create_user(
    connection: sqlite3.Connection,
    *,
    username: str,
    password: str,
    role_name: str,
    email: str | None = None,
) -> str:
    """Create a user and assign an existing role atomically.

    The caller owns the connection and its outer transaction.
    The function uses a SAVEPOINT so a failed operation cannot
    leave a partially created user.
    """

    if not isinstance(username, str):
        raise UserProvisioningError("Username must be text.")

    username = username.strip()

    if not USERNAME_PATTERN.fullmatch(username):
        raise UserProvisioningError(
            "Username must be 3-64 characters and use only "
            "letters, numbers, dots, underscores or hyphens."
        )

    if not isinstance(role_name, str) or not role_name.strip():
        raise UserProvisioningError("A valid role is required.")

    role_name = role_name.strip()

    if not isinstance(password, str):
        raise UserProvisioningError("Password must be text.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserProvisioningError(
            f"Password must contain at least {MIN_PASSWORD_LENGTH} characters."
        )

    if email is not None:
        if not isinstance(email, str):
            raise UserProvisioningError("Email must be text.")

        email = email.strip().casefold() or None

        if email is not None:
            if len(email) > 254 or email.count("@") != 1:
                raise UserProvisioningError("Email address is invalid.")

    role = connection.execute(
        "SELECT id FROM roles WHERE name = ?",
        (role_name,),
    ).fetchone()

    if role is None:
        raise UserProvisioningError("The requested role does not exist.")

    # Expensive hashing happens before opening the write savepoint.
    password_digest = hash_password(password)

    user_id = str(uuid4())
    timestamp = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    connection.execute("SAVEPOINT user_provisioning")

    try:
        connection.execute(
            """
            INSERT INTO users (
                id, username, email, password_hash,
                is_active, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (
                user_id,
                username,
                email,
                password_digest,
                timestamp,
                timestamp,
            ),
        )

        connection.execute(
            """
            INSERT INTO user_roles (user_id, role_id)
            VALUES (?, ?)
            """,
            (user_id, role["id"]),
        )

        connection.execute("RELEASE SAVEPOINT user_provisioning")

    except sqlite3.IntegrityError as exc:
        connection.execute("ROLLBACK TO SAVEPOINT user_provisioning")
        connection.execute("RELEASE SAVEPOINT user_provisioning")

        if "UNIQUE constraint failed" in str(exc):
            raise UserAlreadyExistsError(
                "Username or email is already registered."
            ) from None

        raise UserProvisioningError(
            "User or role assignment could not be created."
        ) from None

    except Exception:
        connection.execute("ROLLBACK TO SAVEPOINT user_provisioning")
        connection.execute("RELEASE SAVEPOINT user_provisioning")
        raise

    return user_id