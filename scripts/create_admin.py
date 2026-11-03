import secrets
import sqlite3
import sys
from getpass import getpass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.db.connection import get_connection
from app.authentication.users import (
    create_user,
    UserProvisioningError,
)


def administrator_exists(connection: sqlite3.Connection) -> bool:
    result = connection.execute(
        """
        SELECT 1
        FROM users u
        JOIN user_roles ur ON ur.user_id = u.id
        JOIN roles r ON r.id = ur.role_id
        WHERE r.name = 'administrator'
          AND u.is_active = 1
        LIMIT 1
        """
    ).fetchone()

    return result is not None


def main() -> int:
    print("SENTINEL AI - Initial Administrator Provisioning")
    print("This tool creates an administrator account locally.")
    print("Passwords are never displayed or passed as command arguments.")
    print()

    try:
        # Early check before requesting credentials.
        with get_connection() as connection:
            if administrator_exists(connection):
                print("Provisioning refused: an active administrator exists.")
                return 2

        username = input("Administrator username: ").strip()
        email = input("Email (optional, press Enter to skip): ").strip()
        email = email or None

        password = getpass("Administrator password: ")
        confirmation = getpass("Confirm administrator password: ")

        if not secrets.compare_digest(password.encode('utf-8'), confirmation.encode('utf-8')):
            print("Provisioning refused: passwords do not match.")
            return 2

        # Recheck under a write lock to prevent concurrent bootstrap attempts.
        with get_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")

            if administrator_exists(connection):
                print("Provisioning refused: an active administrator exists.")
                return 2

            user_id = create_user(
                connection,
                username=username,
                email=email,
                password=password,
                role_name="administrator",
            )

            created_at = connection.execute(
                "SELECT created_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()["created_at"]

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
                    "initial_administrator_created",
                    "user",
                    user_id,
                    "success",
                    created_at,
                ),
            )

        print()
        print("Administrator account created successfully.")
        print("Username:", username)
        print("User ID:", user_id)
        print("Role: administrator")
        print("Password storage: Argon2id")
        print("Audit record: created")

        return 0

    except UserProvisioningError as exc:
        print(f"Provisioning refused: {exc}", file=sys.stderr)
        return 2

    except (sqlite3.Error, OSError):
        print(
            "Provisioning failed due to a database or system error.",
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())