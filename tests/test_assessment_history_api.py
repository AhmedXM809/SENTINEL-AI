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
from app.db.connection import DATABASE_PATH
from app.main import app


BASE_URL = "http://127.0.0.1:8002"
ENDPOINT = "/api/v1/assessments"


class FakeAuthService:
    def __init__(self, users):
        self.users = users

    def get_current_user(self, session_token):
        return self.users.get(session_token)


class TestAssessmentHistoryAPI(unittest.TestCase):

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
        self.memory.execute("PRAGMA query_only = ON")

        schema_version = self.memory.execute(
            "PRAGMA user_version"
        ).fetchone()[0]

        if schema_version != 6:
            self.memory.close()
            raise RuntimeError(
                f"Expected test database schema v6; found v{schema_version}."
            )

        user = self.memory.execute(
            "SELECT id FROM users WHERE is_active = 1 LIMIT 1"
        ).fetchone()

        if user is None:
            self.memory.close()
            raise RuntimeError("No active test user exists in the database copy.")

        user_id = user["id"]

        auditor = AuthenticatedUser(
            user_id=user_id,
            username="history-test-auditor",
            roles=("auditor",),
            permissions=frozenset({"assessments.read"}),
        )

        analyst = AuthenticatedUser(
            user_id=user_id,
            username="history-test-analyst",
            roles=("security_analyst",),
            permissions=frozenset({
                "assessments.read",
                "assessments.execute",
            }),
        )

        execute_only = AuthenticatedUser(
            user_id=user_id,
            username="history-test-execute-only",
            roles=(),
            permissions=frozenset({"assessments.execute"}),
        )

        self.auth = FakeAuthService({
            "history-auditor-session": auditor,
            "history-analyst-session": analyst,
            "history-execute-only-session": execute_only,
        })

        self.cookies = {
            "auditor": {"sentinel_session": "history-auditor-session"},
            "analyst": {"sentinel_session": "history-analyst-session"},
            "execute_only": {
                "sentinel_session": "history-execute-only-session"
            },
        }

        self.original_connection_factory = history_module.get_connection
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
        app.dependency_overrides[get_auth_service] = lambda: self.auth

        self.client = TestClient(app, base_url=BASE_URL)

        self.initial_total_changes = self.memory.total_changes

        self.initial_assessment_count = self.memory.execute(
            "SELECT COUNT(*) FROM assessments"
        ).fetchone()[0]

        self.initial_run_count = self.memory.execute(
            "SELECT COUNT(*) FROM test_runs"
        ).fetchone()[0]

        self.initial_audit_count = self.memory.execute(
            "SELECT COUNT(*) FROM audit_log"
        ).fetchone()[0]

    def tearDown(self):
        self.client.close()

        if self.had_previous_auth_override:
            app.dependency_overrides[get_auth_service] = (
                self.previous_auth_override
            )
        else:
            app.dependency_overrides.pop(get_auth_service, None)

        history_module.get_connection = self.original_connection_factory
        self.memory.close()

    def get_history(self, cookie=None, params=None):
        return self.client.get(
            ENDPOINT,
            cookies=cookie or {},
            params=params or {},
        )

    def assert_database_unchanged(self):
        self.assertEqual(
            self.memory.total_changes,
            self.initial_total_changes,
            "The history GET endpoint must not perform database writes.",
        )

        self.assertEqual(
            self.memory.execute(
                "SELECT COUNT(*) FROM assessments"
            ).fetchone()[0],
            self.initial_assessment_count,
        )

        self.assertEqual(
            self.memory.execute(
                "SELECT COUNT(*) FROM test_runs"
            ).fetchone()[0],
            self.initial_run_count,
        )

        self.assertEqual(
            self.memory.execute(
                "SELECT COUNT(*) FROM audit_log"
            ).fetchone()[0],
            self.initial_audit_count,
        )

    def test_auditor_can_read_history_without_execute_permission(self):
        response = self.get_history(self.cookies["auditor"])

        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertIn("items", payload)
        self.assertIn("pagination", payload)

        self.assertEqual(
            payload["pagination"]["total"],
            self.initial_assessment_count,
        )

        self.assert_database_unchanged()

    def test_analyst_can_read_history(self):
        response = self.get_history(self.cookies["analyst"])

        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json()["items"], list)

        self.assert_database_unchanged()

    def test_execute_only_user_cannot_read_history(self):
        response = self.get_history(self.cookies["execute_only"])

        self.assertEqual(response.status_code, 403)
        self.assert_database_unchanged()

    def test_anonymous_user_cannot_read_history(self):
        response = self.get_history()

        self.assertEqual(response.status_code, 401)
        self.assert_database_unchanged()

    def test_response_contains_only_allowlisted_summary_fields(self):
        response = self.get_history(self.cookies["auditor"])

        self.assertEqual(response.status_code, 200)

        expected_keys = {
            "assessment_id",
            "name",
            "assessment_status",
            "scenario_code",
            "scenario_name",
            "test_run_id",
            "test_run_status",
            "test_run_count",
            "created_at",
            "started_at",
            "completed_at",
        }

        payload = response.json()

        for item in payload["items"]:
            self.assertEqual(set(item.keys()), expected_keys)

        response_text = response.text.lower()

        self.assertNotIn("execution_result", response_text)
        self.assertNotIn("target_profile_id", response_text)
        self.assertNotIn("model_profile_id", response_text)
        self.assertNotIn("redacted_synthetic_canary", response_text)
        self.assertNotIn("canary-", response_text)

        self.assert_database_unchanged()

    def test_history_is_ordered_like_database_records(self):
        response = self.get_history(self.cookies["auditor"])

        self.assertEqual(response.status_code, 200)

        expected_ids = [
            row["id"]
            for row in self.memory.execute("""
                SELECT id
                FROM assessments
                ORDER BY created_at DESC, id DESC
                LIMIT 20 OFFSET 0
            """).fetchall()
        ]

        actual_ids = [
            item["assessment_id"]
            for item in response.json()["items"]
        ]

        self.assertEqual(actual_ids, expected_ids)
        self.assert_database_unchanged()

    def test_pagination_returns_distinct_pages_and_correct_metadata(self):
        first = self.get_history(
            self.cookies["auditor"],
            {"limit": 2, "offset": 0},
        )
        second = self.get_history(
            self.cookies["auditor"],
            {"limit": 2, "offset": 2},
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

        first_payload = first.json()
        second_payload = second.json()

        first_ids = [
            item["assessment_id"]
            for item in first_payload["items"]
        ]
        second_ids = [
            item["assessment_id"]
            for item in second_payload["items"]
        ]

        self.assertEqual(len(first_ids), min(2, self.initial_assessment_count))
        self.assertEqual(
            len(second_ids),
            min(2, max(0, self.initial_assessment_count - 2)),
        )
        self.assertTrue(set(first_ids).isdisjoint(second_ids))

        self.assertEqual(first_payload["pagination"]["limit"], 2)
        self.assertEqual(first_payload["pagination"]["offset"], 0)
        self.assertEqual(
            first_payload["pagination"]["total"],
            self.initial_assessment_count,
        )
        self.assertEqual(
            first_payload["pagination"]["has_more"],
            self.initial_assessment_count > 2,
        )
        self.assertEqual(second_payload["pagination"]["offset"], 2)

        self.assert_database_unchanged()

    def test_empty_page_has_valid_pagination_metadata(self):
        response = self.get_history(
            self.cookies["auditor"],
            {"limit": 10, "offset": self.initial_assessment_count + 10},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"], [])
        self.assertFalse(response.json()["pagination"]["has_more"])
        self.assert_database_unchanged()

    def test_response_disables_caching(self):
        response = self.get_history(self.cookies["auditor"])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        self.assertEqual(response.headers.get("pragma"), "no-cache")

        self.assert_database_unchanged()

    def test_pagination_parameters_are_bounded(self):
        invalid_queries = (
            {"limit": 0},
            {"limit": 101},
            {"offset": -1},
        )

        for params in invalid_queries:
            with self.subTest(params=params):
                response = self.get_history(
                    self.cookies["auditor"],
                    params,
                )
                self.assertEqual(response.status_code, 422)

        self.assert_database_unchanged()


if __name__ == "__main__":
    unittest.main()
