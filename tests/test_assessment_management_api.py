import sqlite3
import sys
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.authentication.routes import ALLOWED_ORIGINS, get_auth_service
from app.authentication.service import AuthenticatedUser
from app.api import assessment_management as management_module
from app.db.connection import DATABASE_PATH
from app.main import app


BASE_URL = sorted(ALLOWED_ORIGINS)[0]
ENDPOINT = "/api/v1/assessments"
VALID_CSRF = "assessment-management-valid-csrf"


class FakeAuthService:
    def __init__(self, users):
        self.users = users

    def get_current_user(self, session_token):
        return self.users.get(session_token)

    def validate_csrf(self, session_token, csrf_token):
        return (
            session_token in self.users
            and csrf_token == VALID_CSRF
        )


class TestAssessmentManagementAPI(unittest.TestCase):

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

        analyst = AuthenticatedUser(
            user_id=user_id,
            username="management-test-analyst",
            roles=("security_analyst",),
            permissions=frozenset({"assessments.create"}),
        )

        auditor = AuthenticatedUser(
            user_id=user_id,
            username="management-test-auditor",
            roles=("auditor",),
            permissions=frozenset({"assessments.read"}),
        )

        execute_only = AuthenticatedUser(
            user_id=user_id,
            username="management-test-execute-only",
            roles=(),
            permissions=frozenset({"assessments.execute"}),
        )

        self.auth = FakeAuthService({
            "management-analyst-session": analyst,
            "management-auditor-session": auditor,
            "management-execute-only-session": execute_only,
        })

        self.cookies = {
            "analyst": {
                "sentinel_session": "management-analyst-session"
            },
            "auditor": {
                "sentinel_session": "management-auditor-session"
            },
            "execute_only": {
                "sentinel_session": "management-execute-only-session"
            },
        }

        self.original_connection_factory = management_module.get_connection
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
                    self.memory.rollback()
                    raise
                else:
                    self.memory.commit()

        management_module.get_connection = memory_connection
        app.dependency_overrides[get_auth_service] = lambda: self.auth

        self.client = TestClient(app, base_url=BASE_URL)

    def tearDown(self):
        self.client.close()

        if self.had_previous_auth_override:
            app.dependency_overrides[get_auth_service] = (
                self.previous_auth_override
            )
        else:
            app.dependency_overrides.pop(get_auth_service, None)

        management_module.get_connection = self.original_connection_factory
        self.memory.close()

    def post_assessment(
        self,
        payload,
        user="analyst",
        csrf=VALID_CSRF,
        include_origin=True,
    ):
        headers = {}

        if include_origin:
            headers["Origin"] = BASE_URL

        if csrf is not None:
            headers["X-CSRF-Token"] = csrf

        return self.client.post(
            ENDPOINT,
            cookies=self.cookies.get(user, {}),
            headers=headers,
            json=payload,
        )

    def record_counts(self):
        return {
            table: self.memory.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in ("assessments", "test_runs", "audit_log")
        }

    def test_create_draft_with_selected_scenarios_without_execution(self):
        before = self.record_counts()

        response = self.post_assessment({
            "name": "AI Security Baseline",
            "scenario_codes": ["AI-001", "AI-003"],
        })

        self.assertEqual(response.status_code, 201, response.text)
        data = response.json()

        self.assertEqual(data["name"], "AI Security Baseline")
        self.assertEqual(data["status"], "draft")
        self.assertEqual(data["scenario_codes"], ["AI-001", "AI-003"])
        self.assertFalse(data["execution_started"])
        self.assertTrue(data["audit_recorded"])
        self.assertEqual(len(data["test_runs"]), 2)

        assessment = self.memory.execute(
            """
            SELECT *
            FROM assessments
            WHERE id = ?
            """,
            (data["assessment_id"],),
        ).fetchone()

        self.assertIsNotNone(assessment)
        self.assertEqual(assessment["status"], "draft")
        self.assertEqual(
            assessment["target_profile_id"],
            "target-testgpt-vulnerable-v1",
        )
        self.assertEqual(
            assessment["model_profile_id"],
            "model-deterministic-mock-v1",
        )
        self.assertIsNone(assessment["started_at"])
        self.assertIsNone(assessment["completed_at"])

        runs = self.memory.execute(
            """
            SELECT
                tc.scenario_code,
                tr.status,
                tr.started_at,
                tr.completed_at,
                tr.execution_result,
                tr.error_summary
            FROM test_runs tr
            JOIN test_cases tc ON tc.id = tr.test_case_id
            WHERE tr.assessment_id = ?
            ORDER BY tc.scenario_code
            """,
            (data["assessment_id"],),
        ).fetchall()

        self.assertEqual(
            {row["scenario_code"] for row in runs},
            {"AI-001", "AI-003"},
        )
        self.assertEqual(len(runs), 2)

        for row in runs:
            self.assertEqual(row["status"], "queued")
            self.assertIsNone(row["started_at"])
            self.assertIsNone(row["completed_at"])
            self.assertIsNone(row["execution_result"])
            self.assertIsNone(row["error_summary"])

        audit = self.memory.execute(
            """
            SELECT action, resource_type, resource_id, outcome
            FROM audit_log
            WHERE resource_id = ?
            """,
            (data["assessment_id"],),
        ).fetchone()

        self.assertIsNotNone(audit)
        self.assertEqual(audit["action"], "assessment.created")
        self.assertEqual(audit["resource_type"], "assessment")
        self.assertEqual(audit["outcome"], "success")

        after = self.record_counts()
        self.assertEqual(after["assessments"], before["assessments"] + 1)
        self.assertEqual(after["test_runs"], before["test_runs"] + 2)
        self.assertEqual(after["audit_log"], before["audit_log"] + 1)

    def test_auditor_cannot_create_assessment(self):
        before = self.record_counts()

        response = self.post_assessment(
            {
                "name": "Permission Test",
                "scenario_codes": ["AI-001"],
            },
            user="auditor",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.record_counts(), before)

    def test_execute_permission_does_not_imply_create_permission(self):
        before = self.record_counts()

        response = self.post_assessment(
            {
                "name": "Permission Test",
                "scenario_codes": ["AI-001"],
            },
            user="execute_only",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.record_counts(), before)

    def test_csrf_token_is_required_and_validated(self):
        before = self.record_counts()

        missing = self.post_assessment(
            {
                "name": "CSRF Test",
                "scenario_codes": ["AI-001"],
            },
            csrf=None,
        )
        self.assertEqual(missing.status_code, 403)

        invalid = self.post_assessment(
            {
                "name": "CSRF Test",
                "scenario_codes": ["AI-001"],
            },
            csrf="invalid-token",
        )
        self.assertEqual(invalid.status_code, 403)

        self.assertEqual(self.record_counts(), before)

    def test_same_origin_header_is_required(self):
        before = self.record_counts()

        response = self.post_assessment(
            {
                "name": "Origin Test",
                "scenario_codes": ["AI-001"],
            },
            include_origin=False,
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.record_counts(), before)

    def test_authentication_is_required(self):
        response = self.client.post(
            ENDPOINT,
            headers={
                "Origin": BASE_URL,
                "X-CSRF-Token": VALID_CSRF,
            },
            json={
                "name": "Authentication Test",
                "scenario_codes": ["AI-001"],
            },
        )

        self.assertEqual(response.status_code, 401)

    def test_invalid_payloads_are_rejected_without_writes(self):
        before = self.record_counts()

        invalid_payloads = (
            {
                "name": "  ",
                "scenario_codes": ["AI-001"],
            },
            {
                "name": "Invalid Empty Selection",
                "scenario_codes": [],
            },
            {
                "name": "Duplicate Selection",
                "scenario_codes": ["AI-001", "AI-001"],
            },
            {
                "name": "Unknown Scenario",
                "scenario_codes": ["AI-999"],
            },
            {
                "name": "Too Many Scenarios",
                "scenario_codes": [
                    "AI-001",
                    "AI-002",
                    "AI-003",
                    "AI-004",
                    "AI-005",
                ],
            },
            {
                "name": "Unexpected Field",
                "scenario_codes": ["AI-001"],
                "target_url": "https://example.invalid",
            },
            {
                "name": "Invalid Scenario Type",
                "scenario_codes": [1],
            },
        )

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                response = self.post_assessment(payload)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(self.record_counts(), before)

    def test_disabled_scenario_cannot_be_selected(self):
        self.memory.execute(
            """
            UPDATE test_cases
            SET is_enabled = 0
            WHERE scenario_code = 'AI-001'
            """
        )
        self.memory.commit()

        before = self.record_counts()

        response = self.post_assessment({
            "name": "Disabled Scenario Test",
            "scenario_codes": ["AI-001"],
        })

        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.record_counts(), before)

    def test_modified_training_profile_is_rejected(self):
        self.memory.execute(
            """
            UPDATE target_profiles
            SET is_enabled = 1
            WHERE id = 'target-testgpt-vulnerable-v1'
            """
        )
        self.memory.commit()

        before = self.record_counts()

        response = self.post_assessment({
            "name": "Profile Validation Test",
            "scenario_codes": ["AI-001"],
        })

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.record_counts(), before)


if __name__ == "__main__":
    unittest.main()