"""CLI for safe SENTINEL AI database initialization."""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.db.connection import DATABASE_PATH
from app.db.migration_runner import MigrationError, initialize_database


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Initialize or safely upgrade the SENTINEL AI SQLite database."
    )
    parser.add_argument(
        "--database", type=Path, default=DATABASE_PATH,
        help="Database file path (default: data/sentinel.db).",
    )
    parser.add_argument(
        "--backup-directory", type=Path, default=None,
        help="Directory for pre-migration database backups.",
    )
    args = parser.parse_args()

    try:
        kwargs = {}
        if args.backup_directory is not None:
            kwargs["backup_directory"] = args.backup_directory
        result = initialize_database(args.database, **kwargs)
    except (MigrationError, sqlite3.Error, OSError, ValueError) as exc:
        print(f"Database initialization failed: {exc}", file=sys.stderr)
        return 1

    print("SENTINEL AI database verification completed.")
    for label, key in (
        ("Status", "status"),
        ("Database", "database"),
        ("Initial schema version", "initial_version"),
        ("Current schema version", "schema_version"),
        ("Application tables", "tables"),
        ("Foreign-key enforcement", "foreign_keys"),
    ):
        print(f"{label}: {result[key]}")
    if result["backup"]:
        print("Pre-migration backup:", result["backup"])
    if result["rbac"]:
        print("RBAC configuration counts:", result["rbac"])
    else:
        print("RBAC seed: skipped (database already current)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
