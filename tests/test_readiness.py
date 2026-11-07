import sqlite3
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient

import app.main as main_module


SCENARIOS = {
    "test-case-ai-001": "AI-001",
    "test-case-ai-002": "AI-002",
    "test-case-ai-003": "AI-003",
    "test-case-ai-004": "AI-004",
}


def make_database(
    schema_version=6,
    omitted_case=None,
    disabled_case=None,
    incorrect_scenario_case=None,
    support_table_count=18,
    foreign_keys=True,
):
    """Build a synthetic in-memory database for readiness tests only."""
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.row_factory = sqlite3.Row

    connection.execute(
        f"PRAGMA foreign_keys = {'ON' if foreign_keys else 'OFF'}"
    )

    connection.execute(
        """
        CREATE TABLE test_cases (
            id TEXT PRIMARY KEY,
            scenario_code TEXT NOT NULL,
            is_enabled INTEGER NOT NULL
        )
        """
    )

    for index in range(support_table_count):
        connection.execute(
            f"CREATE TABLE support_table_{index:02d} (id INTEGER)"
        )

    for case_id, scenario_code in SCENARIOS.items():
        if case_id == omitted_case:
            continue

        if case_id == incorrect_scenario_case:
            scenario_code = "AI-999"

        enabled = 0 if case_id == disabled_case else 1

        connection.execute(
            """
            INSERT INTO test_cases (id, scenario_code, is_enabled)
            VALUES (?, ?, ?)
            """,
            (case_id, scenario_code, enabled),
        )

    connection.execute(f"PRAGMA user_version = {int(schema_version)}")
    return connection


class TestDatabaseReadiness(unittest.TestCase):
    def request_readiness(self, **database_options):
        connection = make_database(**database_options)

        @contextmanager
        def memory_connection():
            yield connection

        try:
            with patch.object(
                main_module,
                "get_connection",
                memory_connection,
            ):
                with TestClient(
                    main_module.app,
                    base_url="http://127.0.0.1",
                ) as client:
                    return client.get("/health/ready")
        finally:
            connection.close()

    def test_complete_v6_database_is_ready(self):
        response = self.request_readiness()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "status": "ready",
                "service": "SENTINEL AI API",
                "database": "connected",
                "schema_version": "6",
                "tables": "19",
                "foreign_keys": "enabled",
                "registered_test_cases": "4",
            },
        )

    def test_v5_database_is_not_ready(self):
        response = self.request_readiness(schema_version=5)
        self.assertEqual(response.status_code, 503)

    def test_missing_scenario_record_is_not_ready(self):
        response = self.request_readiness(
            omitted_case="test-case-ai-002",
        )
        self.assertEqual(response.status_code, 503)

    def test_disabled_scenario_record_is_not_ready(self):
        response = self.request_readiness(
            disabled_case="test-case-ai-003",
        )
        self.assertEqual(response.status_code, 503)

    def test_incorrect_scenario_mapping_is_not_ready(self):
        response = self.request_readiness(
            incorrect_scenario_case="test-case-ai-004",
        )
        self.assertEqual(response.status_code, 503)

    def test_incorrect_application_table_count_is_not_ready(self):
        response = self.request_readiness(support_table_count=17)
        self.assertEqual(response.status_code, 503)

    def test_disabled_foreign_keys_are_not_ready(self):
        response = self.request_readiness(foreign_keys=False)
        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
