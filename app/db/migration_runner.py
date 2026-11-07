"""Safe, versioned SQLite initialization and migration support."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
MIGRATIONS_DIRECTORY = Path(__file__).resolve().parent / "migrations"
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "sentinel.db"
DEFAULT_BACKUP_DIRECTORY = PROJECT_ROOT / "backups" / "database-migrations"
LATEST_SCHEMA_VERSION = 6

EXPECTED_TABLE_COUNTS = {1: 15, 2: 15, 3: 16, 4: 16, 5: 19, 6: 19}
MIGRATION_FILES = {
    2: "002_session_idle_timeout.sql",
    3: "003_http_auth_security.sql",
    4: "004_login_identifier_throttling.sql",
    5: "005_mfa_support.sql",
    6: "006_assessment_test_cases.sql",
}


class MigrationError(RuntimeError):
    """Raised when a database cannot be safely initialized or upgraded."""


def connect_database(database_path: str | Path) -> sqlite3.Connection:
    path = Path(database_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def _application_table_count(connection: sqlite3.Connection) -> int:
    return int(connection.execute(
        """
        SELECT COUNT(*) FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        """
    ).fetchone()[0])


def _verify_database(
    connection: sqlite3.Connection,
    expected_version: int,
) -> int:
    actual_version = int(
        connection.execute("PRAGMA user_version").fetchone()[0]
    )
    if actual_version != expected_version:
        raise MigrationError(
            f"Expected schema version {expected_version}, got {actual_version}."
        )

    expected_tables = EXPECTED_TABLE_COUNTS.get(expected_version)
    actual_tables = _application_table_count(connection)
    if expected_tables is None or actual_tables != expected_tables:
        raise MigrationError(
            f"Schema version {expected_version} expects {expected_tables} "
            f"application tables, found {actual_tables}."
        )

    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise MigrationError("SQLite foreign-key enforcement is not enabled.")

    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise MigrationError(
            f"Database contains {len(violations)} foreign-key violation(s)."
        )
    return actual_tables


def _seed_rbac_if_uninitialized(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    """Seed defaults only when all RBAC tables are completely empty."""

    rbac_tables = (
        "roles",
        "permissions",
        "role_permissions",
        "user_roles",
    )
    counts = {
        table: int(
            connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
        )
        for table in rbac_tables
    }

    if all(count == 0 for count in counts.values()):
        from app.db.seed import seed_rbac
        return seed_rbac(connection)

    # Existing RBAC state may contain intentional permission customizations.
    return {
        "roles": counts["roles"],
        "permissions": counts["permissions"],
        "role_assignments": counts["role_permissions"],
    }


def _run_sql_file(connection: sqlite3.Connection, sql_path: Path) -> None:
    if not sql_path.is_file():
        raise MigrationError(f"Required SQL file is missing: {sql_path.name}")
    sql = sql_path.read_text(encoding="utf-8")
    if not sql.strip():
        raise MigrationError(f"SQL file is empty: {sql_path.name}")

    try:
        # Migrations 005 and 006 own their explicit transactions.
        if "BEGIN IMMEDIATE;" in sql.upper():
            connection.executescript(sql)
        else:
            # The base schema and migrations 002-004 are wrapped atomically.
            connection.executescript(
                "BEGIN IMMEDIATE;\n" + sql + "\nCOMMIT;\n"
            )
    except sqlite3.Error:
        if connection.in_transaction:
            connection.rollback()
        raise


def _create_backup(
    connection: sqlite3.Connection,
    backup_directory: Path,
    schema_version: int,
) -> Path:
    backup_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = backup_directory / (
        f"sentinel-v{schema_version}-before-v{LATEST_SCHEMA_VERSION}-"
        f"{timestamp}.db"
    )
    destination = sqlite3.connect(str(backup_path), timeout=5.0)
    try:
        connection.backup(destination)
        destination.commit()

        integrity_results = destination.execute(
            "PRAGMA integrity_check"
        ).fetchall()
        if len(integrity_results) != 1 or integrity_results[0][0] != "ok":
            raise MigrationError(
                "Created database backup failed SQLite integrity_check."
            )

        backup_version = int(
            destination.execute("PRAGMA user_version").fetchone()[0]
        )
        if backup_version != schema_version:
            raise MigrationError(
                f"Backup schema version mismatch: expected {schema_version}, "
                f"found {backup_version}."
            )

        violations = destination.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        if violations:
            raise MigrationError(
                f"Created database backup contains "
                f"{len(violations)} foreign-key violation(s)."
            )

    except Exception:
        destination.close()
        backup_path.unlink(missing_ok=True)
        raise
    else:
        destination.close()
    return backup_path


def initialize_database(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    backup_directory: str | Path = DEFAULT_BACKUP_DIRECTORY,
) -> dict[str, Any]:
    """Initialize a fresh DB or upgrade v1-v5, backing up before upgrades."""
    path = Path(database_path).expanduser().resolve()
    existed_before = path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect_database(path)
    backup_path: Path | None = None

    try:
        initial_version = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        initial_tables = _application_table_count(connection)

        if initial_version > LATEST_SCHEMA_VERSION:
            raise MigrationError(
                f"Database version {initial_version} is newer than this "
                f"application supports (maximum {LATEST_SCHEMA_VERSION})."
            )

        if initial_version == 0 and initial_tables:
            raise MigrationError(
                "Refusing to initialize an unversioned, non-empty database. "
                "Inspect it and create a verified backup first."
            )

        if initial_version == LATEST_SCHEMA_VERSION:
            table_count = _verify_database(connection, LATEST_SCHEMA_VERSION)

            # Preserve existing RBAC customizations; seed only an empty setup.
            rbac_counts = _seed_rbac_if_uninitialized(connection)
            connection.commit()

            table_count = _verify_database(connection, LATEST_SCHEMA_VERSION)
            return {
                "status": "already_current",
                "database": str(path),
                "initial_version": initial_version,
                "schema_version": LATEST_SCHEMA_VERSION,
                "tables": table_count,
                "foreign_keys": "enabled",
                "backup": None,
                "rbac": rbac_counts,
            }

        if initial_version > 0:
            _verify_database(connection, initial_version)
            if existed_before:
                backup_path = _create_backup(
                    connection,
                    Path(backup_directory).expanduser().resolve(),
                    initial_version,
                )

        current_version = initial_version
        if current_version == 0:
            _run_sql_file(connection, SCHEMA_PATH)
            current_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if current_version != 1:
                raise MigrationError(
                    "Base schema did not set database version to 1."
                )

        while current_version < LATEST_SCHEMA_VERSION:
            next_version = current_version + 1
            migration_name = MIGRATION_FILES.get(next_version)
            if migration_name is None:
                raise MigrationError(
                    f"No migration is defined for version {next_version}."
                )
            _run_sql_file(
                connection,
                MIGRATIONS_DIRECTORY / migration_name,
            )
            applied_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if applied_version != next_version:
                raise MigrationError(
                    f"Migration {migration_name} did not set version "
                    f"{next_version}; found {applied_version}."
                )
            current_version = applied_version

        table_count = _verify_database(connection, LATEST_SCHEMA_VERSION)

        # Preserve existing RBAC customizations during legacy upgrades too.
        rbac_counts = _seed_rbac_if_uninitialized(connection)
        connection.commit()

        table_count = _verify_database(connection, LATEST_SCHEMA_VERSION)
        return {
            "status": "initialized" if initial_version == 0 else "migrated",
            "database": str(path),
            "initial_version": initial_version,
            "schema_version": LATEST_SCHEMA_VERSION,
            "tables": table_count,
            "foreign_keys": "enabled",
            "backup": str(backup_path) if backup_path else None,
            "rbac": rbac_counts,
        }
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()
