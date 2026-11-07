"""Tests for safe SENTINEL AI database initialization and migrations."""
import sqlite3
from pathlib import Path

import pytest

from app.db.migration_runner import (
    MigrationError,
    connect_database,
    initialize_database,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_ROOT / "app" / "db" / "schema.sql"


def assert_registered_test_cases(connection: sqlite3.Connection) -> None:
    expected = {
        "AI-001": "prompt_injection",
        "AI-002": "prompt_injection",
        "AI-003": "agent_tool_security",
        "AI-004": "agent_memory_security",
    }

    rows = connection.execute(
        """
        SELECT scenario_code, category, name, objective,
               expected_behavior, severity_default,
               framework_mapping_json, is_enabled, version
        FROM test_cases
        ORDER BY scenario_code
        """
    ).fetchall()

    assert len(rows) == 4

    for row in rows:
        code = row["scenario_code"]
        assert code in expected
        assert row["category"] == expected[code]
        assert row["name"].strip()
        assert row["objective"].strip()
        assert row["expected_behavior"].strip()
        assert row["severity_default"] is None
        assert row["framework_mapping_json"] is None
        assert row["is_enabled"] == 1
        assert row["version"] == "1.0.0"



def create_version_one_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(
            """
            INSERT INTO users (
                id, username, email, password_hash, is_active,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "test-user-1", "migration-test", None, "x" * 32, 1,
                "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
            ),
        )
        connection.commit()
    finally:
        connection.close()


def test_fresh_database_initializes_to_v5_and_seeds_rbac(
    tmp_path: Path,
) -> None:
    database = tmp_path / "fresh" / "sentinel.db"
    result = initialize_database(database, tmp_path / "backups")

    assert result["status"] == "initialized"
    assert result["initial_version"] == 0
    assert result["schema_version"] == 6
    assert result["tables"] == 19
    assert result["foreign_keys"] == "enabled"
    assert result["backup"] is None
    assert result["rbac"]["roles"] == 3

    connection = connect_database(database)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 6
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT COUNT(*) FROM roles").fetchone()[0] == 3
        assert_registered_test_cases(connection)
    finally:
        connection.close()


def test_v1_upgrade_creates_backup_and_preserves_user(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    backup_directory = tmp_path / "backups"
    create_version_one_database(database)

    result = initialize_database(database, backup_directory)

    assert result["status"] == "migrated"
    assert result["initial_version"] == 1
    assert result["schema_version"] == 6
    assert result["tables"] == 19
    assert result["backup"] is not None
    assert result["rbac"]["roles"] == 3
    assert result["rbac"]["permissions"] == 17
    assert result["rbac"]["role_assignments"] == 30

    backup = sqlite3.connect(result["backup"])
    try:
        assert backup.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert backup.execute("PRAGMA foreign_key_check").fetchall() == []
        assert backup.execute("PRAGMA user_version").fetchone()[0] == 1
        assert backup.execute(
            "SELECT username FROM users WHERE id = ?",
            ("test-user-1",),
        ).fetchone()[0] == "migration-test"
    finally:
        backup.close()

    upgraded = connect_database(database)
    try:
        assert upgraded.execute("PRAGMA user_version").fetchone()[0] == 6
        assert upgraded.execute(
            "SELECT username FROM users WHERE id = ?",
            ("test-user-1",),
        ).fetchone()[0] == "migration-test"
        assert upgraded.execute("PRAGMA foreign_key_check").fetchall() == []
        assert_registered_test_cases(upgraded)
    finally:
        upgraded.close()


def test_current_database_is_verified_without_backup(tmp_path: Path) -> None:
    database = tmp_path / "current.db"
    backup_directory = tmp_path / "backups"

    first = initialize_database(database, backup_directory)
    second = initialize_database(database, backup_directory)

    assert first["status"] == "initialized"
    assert second["status"] == "already_current"
    assert second["schema_version"] == 6
    assert second["tables"] == 19
    assert second["backup"] is None
    assert not backup_directory.exists()



def test_v5_upgrade_creates_backup_and_registers_test_cases(
    tmp_path: Path,
) -> None:
    database = tmp_path / "version-five.db"
    backup_directory = tmp_path / "backups"

    # Create the current database, then reconstruct its pre-006 state.
    initialize_database(database, backup_directory)

    connection = connect_database(database)
    try:
        connection.execute("DELETE FROM test_cases")
        connection.execute("PRAGMA user_version = 5")
        connection.commit()
    finally:
        connection.close()

    result = initialize_database(database, backup_directory)

    assert result["status"] == "migrated"
    assert result["initial_version"] == 5
    assert result["schema_version"] == 6
    assert result["tables"] == 19
    assert result["backup"] is not None

    backup = sqlite3.connect(result["backup"])
    try:
        assert backup.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert backup.execute("PRAGMA user_version").fetchone()[0] == 5
        assert backup.execute(
            "SELECT COUNT(*) FROM test_cases"
        ).fetchone()[0] == 0
    finally:
        backup.close()

    upgraded = connect_database(database)
    try:
        assert upgraded.execute("PRAGMA user_version").fetchone()[0] == 6
        assert upgraded.execute("PRAGMA foreign_key_check").fetchall() == []
        assert_registered_test_cases(upgraded)
    finally:
        upgraded.close()


def test_unversioned_nonempty_database_is_refused_unchanged(
    tmp_path: Path,
) -> None:
    database = tmp_path / "unknown.db"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE unexpected_data (value TEXT)")
        connection.execute(
            "INSERT INTO unexpected_data(value) VALUES (?)", ("preserve-me",)
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(MigrationError, match="unversioned, non-empty"):
        initialize_database(database, tmp_path / "backups")

    check = sqlite3.connect(database)
    try:
        assert check.execute(
            "SELECT value FROM unexpected_data"
        ).fetchone()[0] == "preserve-me"
        assert check.execute("PRAGMA user_version").fetchone()[0] == 0
    finally:
        check.close()


def test_newer_database_version_is_refused(tmp_path: Path) -> None:
    database = tmp_path / "future.db"
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA user_version = 99")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(MigrationError, match="newer than this application"):
        initialize_database(database)

def test_current_database_preserves_rbac_customizations_and_user_role(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rbac-recovery.db"
    backup_directory = tmp_path / "backups"

    initialize_database(database, backup_directory)

    connection = connect_database(database)
    try:
        connection.execute(
            """
            INSERT INTO users (
                id, username, email, password_hash, is_active,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "rbac-recovery-user",
                "rbac-recovery-test",
                None,
                "x" * 32,
                1,
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )

        administrator_id = connection.execute(
            "SELECT id FROM roles WHERE name = 'administrator'"
        ).fetchone()[0]

        connection.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
            ("rbac-recovery-user", administrator_id),
        )

        missing_mapping = connection.execute(
            """
            SELECT role_id, permission_id
            FROM role_permissions
            WHERE role_id = ?
            LIMIT 1
            """,
            (administrator_id,),
        ).fetchone()

        assert missing_mapping is not None

        connection.execute(
            """
            DELETE FROM role_permissions
            WHERE role_id = ? AND permission_id = ?
            """,
            tuple(missing_mapping),
        )
        connection.commit()

        remaining_mappings = connection.execute(
            "SELECT COUNT(*) FROM role_permissions"
        ).fetchone()[0]

        assert remaining_mappings == 29

    finally:
        connection.close()

    result = initialize_database(database, backup_directory)

    assert result["status"] == "already_current"
    assert result["rbac"] is not None
    assert result["rbac"]["roles"] == 3
    assert result["rbac"]["permissions"] == 17
    assert result["rbac"]["role_assignments"] == 29

    connection = connect_database(database)
    try:
        restored = connection.execute(
            """
            SELECT COUNT(*)
            FROM role_permissions
            WHERE role_id = ? AND permission_id = ?
            """,
            tuple(missing_mapping),
        ).fetchone()[0]

        # Initialization must not undo a deliberate permission revocation.
        assert restored == 0

        preserved_user_role = connection.execute(
            """
            SELECT COUNT(*)
            FROM user_roles
            WHERE user_id = ? AND role_id = ?
            """,
            ("rbac-recovery-user", administrator_id),
        ).fetchone()[0]

        assert preserved_user_role == 1

    finally:
        connection.close()

    assert not backup_directory.exists()


def test_current_database_retries_rbac_seed_after_rolled_back_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.db import seed as seed_module

    database = tmp_path / "rbac-seed-retry.db"
    backup_directory = tmp_path / "backups"
    original_seed = seed_module.seed_rbac

    def fail_after_seed(connection: sqlite3.Connection):
        original_seed(connection)
        raise RuntimeError("Simulated failure after RBAC inserts.")

    monkeypatch.setattr(seed_module, "seed_rbac", fail_after_seed)

    with pytest.raises(RuntimeError, match="Simulated failure"):
        initialize_database(database, backup_directory)

    # Schema migrations remain committed, but the failed RBAC transaction
    # must leave all four RBAC tables empty.
    connection = connect_database(database)
    try:
        assert connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0] == 6

        for table in (
            "roles",
            "permissions",
            "role_permissions",
            "user_roles",
        ):
            assert connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0] == 0
    finally:
        connection.close()

    monkeypatch.setattr(seed_module, "seed_rbac", original_seed)

    result = initialize_database(database, backup_directory)

    assert result["status"] == "already_current"
    assert result["rbac"]["roles"] == 3
    assert result["rbac"]["permissions"] == 17
    assert result["rbac"]["role_assignments"] == 30

def test_v1_upgrade_preserves_existing_rbac_customizations(
    tmp_path: Path,
) -> None:
    from app.db.seed import seed_rbac

    database = tmp_path / "legacy-rbac.db"
    backup_directory = tmp_path / "backups"
    create_version_one_database(database)

    connection = connect_database(database)
    try:
        seed_rbac(connection)

        administrator_id = connection.execute(
            "SELECT id FROM roles WHERE name = 'administrator'"
        ).fetchone()[0]

        connection.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
            ("test-user-1", administrator_id),
        )

        mapping = connection.execute(
            """
            SELECT role_id, permission_id
            FROM role_permissions
            WHERE role_id = ?
            LIMIT 1
            """,
            (administrator_id,),
        ).fetchone()

        assert mapping is not None

        connection.execute(
            """
            DELETE FROM role_permissions
            WHERE role_id = ? AND permission_id = ?
            """,
            tuple(mapping),
        )
        connection.commit()
    finally:
        connection.close()

    result = initialize_database(database, backup_directory)

    assert result["status"] == "migrated"
    assert result["schema_version"] == 6

    connection = connect_database(database)
    try:
        preserved_mapping = connection.execute(
            """
            SELECT COUNT(*)
            FROM role_permissions
            WHERE role_id = ? AND permission_id = ?
            """,
            tuple(mapping),
        ).fetchone()[0]

        assert preserved_mapping == 0

        preserved_user_role = connection.execute(
            """
            SELECT COUNT(*)
            FROM user_roles
            WHERE user_id = ? AND role_id = ?
            """,
            ("test-user-1", administrator_id),
        ).fetchone()[0]

        assert preserved_user_role == 1
    finally:
        connection.close()
