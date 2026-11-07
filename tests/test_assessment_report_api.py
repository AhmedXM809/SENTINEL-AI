import json
import sqlite3
import sys
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.authentication.routes import get_auth_service
from app.authentication.service import AuthenticatedUser
from app.api import history as history_module
from app.core import (
    ai_security,
    ai002_indirect,
    ai003_tool_misuse,
    ai004_memory_poisoning,
)
from app.db.connection import DATABASE_PATH
from app.main import app


ENDPOINT = "/api/v1/assessments"

EXPECTED_SCENARIOS = {
    "AI-001",
    "AI-002",
    "AI-003",
    "AI-004",
}

FORBIDDEN_KEYS = {
    "execution_result",
    "target_profile_ids",
    "model_profile_id",
    "output",
    "synthetic_response",
    "source_attestation",
    "content_sha256",
    "content",
    "memory_id",
    "source_id",
    "ingestion_decisions",
    "retrieval_decisions",
    "results",
}

CANARIES = (
    ai_security.SYNTHETIC_CANARY,
    ai002_indirect.SYNTHETIC_RAG_CANARY,
    ai003_tool_misuse.SYNTHETIC_CANARY,
    ai004_memory_poisoning.SYNTHETIC_MEMORY_CANARY,
)


def collect_keys(value):
    keys = set()

    if isinstance(value, dict):
        for key, item in value.items():
            keys.add(key)
            keys.update(collect_keys(item))

    elif isinstance(value, list):
        for item in value:
            keys.update(collect_keys(item))

    return keys


class FakeAuthService:
    def __init__(self, users):
        self.users = users

    def get_current_user(self, session_token):
        return self.users.get(session_token)


class TestAssessmentReportAPI(unittest.TestCase):

    def setUp(self):
        source = sqlite3.connect(
            f"file:{Path(DATABASE_PATH).resolve().as_posix()}?mode=ro",
            uri=True,
        )

        self.memory = sqlite3.connect(
            ":memory:",
            check_same_thread=False,
        )

        source.backup(self.memory)
        source.close()

        self.memory.row_factory = sqlite3.Row
        self.memory.execute("PRAGMA foreign_keys = ON")

        schema_version = self.memory.execute(
            "PRAGMA user_version"
        ).fetchone()[0]

        if schema_version != 6:
            self.memory.close()
            raise RuntimeError(
                f"Expected schema v6; found v{schema_version}."
            )

        user = self.memory.execute(
            "SELECT id FROM users WHERE is_active = 1 LIMIT 1"
        ).fetchone()

        if user is None:
            self.memory.close()
            raise RuntimeError("No active test user exists.")

        user_id = user["id"]

        auditor = AuthenticatedUser(
            user_id=user_id,
            username="report-test-auditor",
            roles=("auditor",),
            permissions=frozenset({"assessments.read"}),
        )

        execute_only = AuthenticatedUser(
            user_id=user_id,
            username="report-test-execute-only",
            roles=(),
            permissions=frozenset({"assessments.execute"}),
        )

        other_auditor = AuthenticatedUser(
            user_id="report-test-different-user",
            username="report-test-other-auditor",
            roles=("auditor",),
            permissions=frozenset({"assessments.read"}),
        )

        self.auth = FakeAuthService({
            "report-auditor-session": auditor,
            "report-execute-only-session": execute_only,
            "report-other-auditor-session": other_auditor,
        })

        self.cookies = {
            "auditor": {
                "sentinel_session": "report-auditor-session"
            },
            "execute_only": {
                "sentinel_session": "report-execute-only-session"
            },
            "other_auditor": {
                "sentinel_session": "report-other-auditor-session"
            },
        }

        self.original_connection_factory = (
            history_module.get_connection
        )

        self.previous_auth_override = app.dependency_overrides.get(
            get_auth_service
        )

        self.had_previous_auth_override = (
            get_auth_service in app.dependency_overrides
        )

        self.lock = threading.RLock()

        @contextmanager
        def memory_connection():
            with self.lock:
                try:
                    yield self.memory
                except BaseException:
                    raise
                else:
                    self.memory.commit()

        history_module.get_connection = memory_connection
        app.dependency_overrides[get_auth_service] = (
            lambda: self.auth
        )

        self.client = TestClient(
            app,
            base_url="http://127.0.0.1:8002",
        )

        rows = self.memory.execute("""
            SELECT
                a.id AS assessment_id,
                tr.id AS test_run_id,
                tc.scenario_code

            FROM assessments a

            JOIN test_runs tr
                ON tr.assessment_id = a.id

            JOIN test_cases tc
                ON tc.id = tr.test_case_id

            WHERE a.status = 'completed'
              AND tr.status = 'completed'
              AND tr.execution_result IS NOT NULL
            ORDER BY tc.scenario_code, a.created_at, tr.completed_at, a.id, tr.id
        """).fetchall()

        self.records = {
            row["scenario_code"]: {
                "assessment_id": row["assessment_id"],
                "test_run_id": row["test_run_id"],
            }
            for row in rows
        }

        if set(self.records) != EXPECTED_SCENARIOS:
            raise RuntimeError(
                "Test database does not contain exactly one "
                "record for every supported scenario."
            )

    def tearDown(self):
        self.client.close()

        if self.had_previous_auth_override:
            app.dependency_overrides[get_auth_service] = (
                self.previous_auth_override
            )
        else:
            app.dependency_overrides.pop(
                get_auth_service,
                None,
            )

        history_module.get_connection = (
            self.original_connection_factory
        )

        self.memory.close()

    def get_report(self, assessment_id, cookie=None):
        return self.client.get(
            f"{ENDPOINT}/{assessment_id}/report",
            cookies=cookie or {},
        )

    def database_snapshot(self):
        counts = {}

        for table in (
            "assessments",
            "test_runs",
            "audit_log",
        ):
            counts[table] = self.memory.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

        return {
            "total_changes": self.memory.total_changes,
            "counts": counts,
        }

    def assert_database_unchanged(self, before):
        self.assertEqual(
            self.database_snapshot(),
            before,
            "Report GET endpoint must not modify database records.",
        )

    def test_all_four_scenario_reports_are_sanitized(self):
        expected_top_level_keys = {
            "report_schema_version",
            "assessment",
            "test_run",
            "scenario",
            "summary",
            "comparison",
            "metrics",
            "scope",
            "limitations",
        }

        for scenario_code in sorted(EXPECTED_SCENARIOS):
            with self.subTest(scenario=scenario_code):

                record = self.records[scenario_code]
                before = self.database_snapshot()

                response = self.get_report(
                    record["assessment_id"],
                    self.cookies["auditor"],
                )

                self.assertEqual(response.status_code, 200)

                payload = response.json()

                self.assertEqual(
                    set(payload),
                    expected_top_level_keys,
                )

                self.assertEqual(
                    payload["report_schema_version"],
                    1,
                )

                self.assertEqual(
                    payload["scenario"]["code"],
                    scenario_code,
                )

                self.assertEqual(
                    payload["summary"]["blue_team_control"],
                    "PASS",
                )

                self.assertTrue(
                    payload["scope"]["simulation_only"]
                )

                self.assertEqual(
                    payload["assessment"]["assessment_id"],
                    record["assessment_id"],
                )

                self.assertEqual(
                    payload["test_run"]["test_run_id"],
                    record["test_run_id"],
                )

                actual_keys = collect_keys(payload)
                leaked_keys = actual_keys.intersection(
                    FORBIDDEN_KEYS
                )

                self.assertFalse(
                    leaked_keys,
                    f"Forbidden response keys: {leaked_keys}",
                )

                serialized = response.text.lower()

                for canary in CANARIES:
                    self.assertNotIn(
                        canary.lower(),
                        serialized,
                    )

                self.assertEqual(
                    response.headers.get("cache-control"),
                    "no-store",
                )

                self.assertEqual(
                    response.headers.get("pragma"),
                    "no-cache",
                )

                self.assert_database_unchanged(before)

    def test_auditor_can_read_report_without_execute_permission(self):
        record = self.records["AI-001"]
        before = self.database_snapshot()

        response = self.get_report(
            record["assessment_id"],
            self.cookies["auditor"],
        )

        self.assertEqual(response.status_code, 200)
        self.assert_database_unchanged(before)

    def test_execute_only_user_cannot_read_report(self):
        record = self.records["AI-001"]
        before = self.database_snapshot()

        response = self.get_report(
            record["assessment_id"],
            self.cookies["execute_only"],
        )

        self.assertEqual(response.status_code, 403)
        self.assert_database_unchanged(before)

    def test_anonymous_user_cannot_read_report(self):
        record = self.records["AI-001"]
        before = self.database_snapshot()

        response = self.get_report(record["assessment_id"])

        self.assertEqual(response.status_code, 401)
        self.assert_database_unchanged(before)

    def test_report_visibility_matches_global_auditor_model(self):
        record = self.records["AI-001"]
        before = self.database_snapshot()

        response = self.get_report(
            record["assessment_id"],
            self.cookies["other_auditor"],
        )

        self.assertEqual(response.status_code, 200)
        self.assert_database_unchanged(before)

    def test_unknown_assessment_returns_not_found(self):
        before = self.database_snapshot()

        response = self.get_report(
            "assessment-does-not-exist",
            self.cookies["auditor"],
        )

        self.assertEqual(response.status_code, 404)
        self.assert_database_unchanged(before)

    def test_malformed_execution_json_returns_generic_error(self):
        record = self.records["AI-001"]

        self.memory.execute(
            """
            UPDATE test_runs
            SET execution_result = ?
            WHERE id = ?
            """,
            (
                '{"malformed": ',
                record["test_run_id"],
            ),
        )
        self.memory.commit()

        before = self.database_snapshot()

        response = self.get_report(
            record["assessment_id"],
            self.cookies["auditor"],
        )

        self.assertEqual(response.status_code, 500)

        self.assertEqual(
            response.json()["detail"],
            "The stored assessment report could not be validated.",
        )

        self.assertNotIn(
            '{"malformed": ',
            response.text,
        )

        self.assert_database_unchanged(before)

    def test_unrecognized_stored_fields_and_canaries_never_leak(self):
        record = self.records["AI-001"]

        stored = self.memory.execute(
            """
            SELECT execution_result
            FROM test_runs
            WHERE id = ?
            """,
            (record["test_run_id"],),
        ).fetchone()["execution_result"]

        execution_record = json.loads(stored)

        execution_record["untrusted_extra_payload"] = {
            "source_attestation": "synthetic-private-attestation",
            "content_sha256": "synthetic-private-hash",
            "content": "synthetic-private-content",
            "synthetic_response": CANARIES[0],
            "additional_canaries": list(CANARIES),
        }

        execution_record["simulation"]["unexpected_raw_output"] = (
            CANARIES[1]
        )

        self.memory.execute(
            """
            UPDATE test_runs
            SET execution_result = ?
            WHERE id = ?
            """,
            (
                json.dumps(execution_record),
                record["test_run_id"],
            ),
        )
        self.memory.commit()

        before = self.database_snapshot()

        response = self.get_report(
            record["assessment_id"],
            self.cookies["auditor"],
        )

        self.assertEqual(response.status_code, 200)

        serialized = response.text.lower()

        for canary in CANARIES:
            self.assertNotIn(canary.lower(), serialized)

        actual_keys = collect_keys(response.json())

        self.assertFalse(
            actual_keys.intersection(FORBIDDEN_KEYS)
        )

        self.assertNotIn(
            "untrusted_extra_payload",
            actual_keys,
        )

        self.assertNotIn(
            "unexpected_raw_output",
            actual_keys,
        )

        self.assertDatabase = self.assert_database_unchanged
        self.assert_database_unchanged(before)


if __name__ == "__main__":
    unittest.main()