import os
os.environ["SENTINEL_ALLOWED_ORIGINS"] = "http://127.0.0.1:8002"
os.environ["SENTINEL_COOKIE_SECURE"] = "false"

import json
import sqlite3
import sys
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(r"D:\Cybersecurity-Projects\SENTINEL-AI")
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.authentication.routes import get_auth_service
from app.authentication.service import AuthenticatedUser
from app.api import assessments as assessment_module
from app.db.connection import DATABASE_PATH
from app.main import app


BASE_URL = "http://127.0.0.1:8002"
ENDPOINT = "/api/v1/simulations/AI-001/run"
ENDPOINT_AI002 = "/api/v1/simulations/AI-002/run"
ENDPOINT_AI003 = "/api/v1/simulations/AI-003/run"


class FakeAuthService:
    def __init__(self, users):
        self.users = users

    def get_current_user(self, session_token):
        return self.users.get(session_token)

    def validate_csrf(self, session_token, csrf_token):
        return (
            session_token in self.users
            and csrf_token == "test-csrf"
        )


class TestAI001SimulationAPI(unittest.TestCase):

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

        administrator = self.memory.execute(
            """
            SELECT u.id, u.username
            FROM users u
            JOIN user_roles ur ON ur.user_id = u.id
            JOIN roles r ON r.id = ur.role_id
            WHERE u.is_active = 1
              AND r.name = 'administrator'
            LIMIT 1
            """
        ).fetchone()

        self.assertIsNotNone(administrator)

        user_id = administrator["id"]

        admin = AuthenticatedUser(
            user_id=user_id,
            username="test-admin",
            roles=("administrator",),
            permissions=frozenset({
                "targets.read",
                "models.read",
                "assessments.execute",
            }),
        )

        analyst = AuthenticatedUser(
            user_id=user_id,
            username="test-analyst",
            roles=("security_analyst",),
            permissions=frozenset({
                "targets.read",
                "models.read",
                "assessments.execute",
            }),
        )

        auditor = AuthenticatedUser(
            user_id=user_id,
            username="test-auditor",
            roles=("auditor",),
            permissions=frozenset({
                "assessments.read",
            }),
        )

        self.auth = FakeAuthService({
            "admin-test-session": admin,
            "analyst-test-session": analyst,
            "auditor-test-session": auditor,
            "execute-only-test-session": AuthenticatedUser(
                user_id=user_id,
                username="test-execute-only",
                roles=(),
                permissions=frozenset({"assessments.execute"}),
            ),
        })

        self.lock = threading.RLock()

        @contextmanager
        def memory_connection():
            with self.lock:
                try:
                    yield self.memory
                    self.memory.commit()
                except BaseException:
                    self.memory.rollback()
                    raise

        self.original_connection_factory = assessment_module.get_connection
        assessment_module.get_connection = memory_connection
        app.dependency_overrides[get_auth_service] = lambda: self.auth

        self.client = TestClient(
            app,
            base_url=BASE_URL,
        )

        self.admin_cookie = {"sentinel_session": "admin-test-session"}
        self.analyst_cookie = {"sentinel_session": "analyst-test-session"}
        self.auditor_cookie = {"sentinel_session": "auditor-test-session"}

        self.headers = {
            "Origin": BASE_URL,
            "X-CSRF-Token": "test-csrf",
        }

        targets = self.memory.execute(
            """
            SELECT id, target_type, security_mode, is_enabled
            FROM target_profiles
            WHERE id IN (?, ?)
            """,
            (
                "target-testgpt-vulnerable-v1",
                "target-testgpt-secure-v1",
            ),
        ).fetchall()

        self.assertEqual(len(targets), 2)
        self.assertTrue(all(row["is_enabled"] == 0 for row in targets))

        model = self.memory.execute(
            """
            SELECT provider_type, model_identifier, configuration_json
            FROM model_profiles
            WHERE id = ?
            """,
            ("model-deterministic-mock-v1",),
        ).fetchone()

        self.assertIsNotNone(model)
        self.assertEqual(model["provider_type"], "deterministic_mock")

        self.initial_assessments = self.memory.execute(
            "SELECT COUNT(*) FROM assessments"
        ).fetchone()[0]

        self.initial_runs = self.memory.execute(
            "SELECT COUNT(*) FROM test_runs"
        ).fetchone()[0]

        self.initial_findings = self.memory.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]

        self.initial_evidence = self.memory.execute(
            "SELECT COUNT(*) FROM evidence"
        ).fetchone()[0]

        self.initial_ai001_audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-001'
            """
        ).fetchone()[0]

        self.initial_ai002_audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-002'
            """
        ).fetchone()[0]

        self.initial_ai003_audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-003'
            """
        ).fetchone()[0]

        self.initial_security_events = self.memory.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.pop(get_auth_service, None)
        assessment_module.get_connection = self.original_connection_factory
        self.memory.close()

    def post(self, cookie=None, headers=None):
        return self.client.post(
            ENDPOINT,
            cookies=cookie or {},
            headers=headers or {"Origin": BASE_URL},
        )

    def post_ai002(self, cookie=None, headers=None):
        return self.client.post(
            ENDPOINT_AI002,
            cookies=cookie or {},
            headers=headers or {"Origin": BASE_URL},
        )

    def post_ai003(self, cookie=None, headers=None):
        return self.client.post(
            ENDPOINT_AI003,
            cookies=cookie or {},
            headers=headers or {"Origin": BASE_URL},
        )

    def test_anonymous_user_is_rejected(self):
        response = self.post()

        self.assertEqual(response.status_code, 401)

    def test_auditor_without_execute_permission_is_rejected(self):
        response = self.post(
            self.auditor_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 403)

    def test_missing_csrf_is_rejected(self):
        response = self.post(
            self.analyst_cookie,
            {"Origin": BASE_URL},
        )

        self.assertEqual(response.status_code, 403)

    def test_untrusted_origin_is_rejected(self):
        response = self.post(
            self.admin_cookie,
            {
                "Origin": "http://untrusted.invalid",
                "X-CSRF-Token": "test-csrf",
            },
        )

        self.assertEqual(response.status_code, 403)

    def test_execute_permission_without_target_read_is_rejected(self):
        response = self.post(
            {"sentinel_session": "execute-only-test-session"},
            self.headers,
        )

        self.assertEqual(response.status_code, 403)
    def test_analyst_can_execute_controlled_ai001(self):
        response = self.post(
            self.analyst_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("cache-control"),
            "no-store",
        )

        body = response.json()
        result = body["simulation"]

        self.assertEqual(result["scenario_id"], "AI-001")
        self.assertTrue(result["simulation_only"])
        self.assertFalse(result["persisted"])
        self.assertFalse(result["targets_enabled"])
        self.assertFalse(result["external_provider_used"])

        self.assertEqual(
            result["evaluation"]["blue_team_control"],
            "PASS",
        )
        self.assertTrue(
            result["evaluation"]["vulnerable_target_disclosed_canary"]
        )
        self.assertTrue(
            result["evaluation"]["secure_target_blocked"]
        )
        self.assertFalse(
            result["evaluation"]["secure_target_disclosed_canary"]
        )

        self.assertTrue(body["audit_recorded"])
        self.assertFalse(body["assessment_created"])
        self.assertFalse(body["test_run_created"])
        self.assertFalse(body["finding_created"])
        self.assertFalse(body["evidence_persisted"])

        audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-001'
            """
        ).fetchone()[0]

        self.assertEqual(audit_count, self.initial_ai001_audit_count + 1)

        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM assessments").fetchone()[0],
            self.initial_assessments,
        )
        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM test_runs").fetchone()[0],
            self.initial_runs,
        )
        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            self.initial_findings,
        )
        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            self.initial_evidence,
        )

        self.assertTrue(
            all(
                row["is_enabled"] == 0
                for row in self.memory.execute(
                    "SELECT is_enabled FROM target_profiles"
                )
            )
        )

    def test_administrator_can_execute_ai001(self):
        response = self.post(
            self.admin_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["simulation"]["scenario_id"],
            "AI-001",
        )

    def test_enabled_target_is_rejected(self):
        self.memory.execute(
            """
            UPDATE target_profiles
            SET is_enabled = 1
            WHERE id = ?
            """,
            ("target-testgpt-secure-v1",),
        )
        self.memory.commit()

        audit_before = self.memory.execute(
            "SELECT COUNT(*) FROM audit_log"
        ).fetchone()[0]

        response = self.post(
            self.analyst_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 409)

        audit_after = self.memory.execute(
            "SELECT COUNT(*) FROM audit_log"
        ).fetchone()[0]

        self.assertEqual(audit_before, audit_after)

    def test_unsafe_mock_configuration_is_rejected(self):
        config = json.dumps({
            "external_network": True,
            "filesystem_access": False,
            "shell_access": False,
            "synthetic_data_only": True,
        })

        self.memory.execute(
            """
            UPDATE model_profiles
            SET configuration_json = ?
            WHERE id = ?
            """,
            (
                config,
                "model-deterministic-mock-v1",
            ),
        )
        self.memory.commit()

        response = self.post(
            self.analyst_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 409)

    def test_repeat_execution_is_deterministic_and_audited(self):
        first = self.post(self.analyst_cookie, self.headers)
        second = self.post(self.analyst_cookie, self.headers)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

        self.assertEqual(
            first.json()["simulation"],
            second.json()["simulation"],
        )

        audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-001'
            """
        ).fetchone()[0]

        self.assertEqual(audit_count, self.initial_ai001_audit_count + 2)

    def test_ai002_anonymous_user_is_rejected(self):
        response = self.post_ai002()

        self.assertEqual(response.status_code, 401)

    def test_ai002_auditor_without_execute_permission_is_rejected(self):
        response = self.post_ai002(
            self.auditor_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 403)

    def test_ai002_execute_only_permission_without_target_read_is_rejected(self):
        response = self.post_ai002(
            {"sentinel_session": "execute-only-test-session"},
            self.headers,
        )

        self.assertEqual(response.status_code, 403)

    def test_ai002_missing_csrf_is_rejected(self):
        response = self.post_ai002(
            self.analyst_cookie,
            {"Origin": BASE_URL},
        )

        self.assertEqual(response.status_code, 403)

    def test_ai002_untrusted_origin_is_rejected(self):
        response = self.post_ai002(
            self.admin_cookie,
            {
                "Origin": "http://untrusted.invalid",
                "X-CSRF-Token": "test-csrf",
            },
        )

        self.assertEqual(response.status_code, 403)

    def test_ai002_analyst_can_execute_controlled_simulation(self):
        response = self.post_ai002(
            self.analyst_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("cache-control"),
            "no-store",
        )

        body = response.json()
        result = body["simulation"]

        self.assertEqual(result["scenario_id"], "AI-002")
        self.assertTrue(result["simulation_only"])
        self.assertFalse(result["persisted"])
        self.assertFalse(result["targets_enabled"])
        self.assertFalse(result["external_provider_used"])
        self.assertFalse(result["retrieved_document_content_returned"])

        self.assertEqual(
            result["document_inspection"]["rule_ids"],
            [
                "RAG-INDIRECT-OVERRIDE",
                "RAG-ROLE-ESCALATION",
                "RAG-SYNTHETIC-DATA-EXFILTRATION",
            ],
        )

        self.assertTrue(
            result["evaluation"]["indirect_injection_detected"]
        )
        self.assertTrue(
            result["evaluation"]["vulnerable_target_disclosed_canary"]
        )
        self.assertTrue(
            result["evaluation"]["secure_target_blocked"]
        )
        self.assertTrue(
            result["evaluation"]["secure_target_treated_document_as_untrusted"]
        )
        self.assertFalse(
            result["evaluation"]["secure_target_disclosed_canary"]
        )
        self.assertEqual(
            result["evaluation"]["blue_team_control"],
            "PASS",
        )

        # The raw synthetic retrieved document must not be returned.
        self.assertNotIn(
            "UNTRUSTED DOCUMENT INSTRUCTION",
            str(result),
        )

        self.assertTrue(body["audit_recorded"])
        self.assertFalse(body["assessment_created"])
        self.assertFalse(body["test_run_created"])
        self.assertFalse(body["finding_created"])
        self.assertFalse(body["evidence_persisted"])

        audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-002'
            """
        ).fetchone()[0]

        self.assertEqual(
            audit_count,
            self.initial_ai002_audit_count + 1,
        )

        self.assertEqual(
            self.memory.execute(
                "SELECT COUNT(*) FROM assessments"
            ).fetchone()[0],
            self.initial_assessments,
        )
        self.assertEqual(
            self.memory.execute(
                "SELECT COUNT(*) FROM test_runs"
            ).fetchone()[0],
            self.initial_runs,
        )
        self.assertEqual(
            self.memory.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0],
            self.initial_findings,
        )
        self.assertEqual(
            self.memory.execute(
                "SELECT COUNT(*) FROM evidence"
            ).fetchone()[0],
            self.initial_evidence,
        )
        self.assertEqual(
            self.memory.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0],
            self.initial_security_events,
        )

        self.assertTrue(
            all(
                row["is_enabled"] == 0
                for row in self.memory.execute(
                    "SELECT is_enabled FROM target_profiles"
                )
            )
        )

    def test_ai002_enabled_target_is_rejected_without_audit(self):
        self.memory.execute(
            """
            UPDATE target_profiles
            SET is_enabled = 1
            WHERE id = ?
            """,
            ("target-testgpt-secure-v1",),
        )
        self.memory.commit()

        response = self.post_ai002(
            self.analyst_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 409)

        audit_after = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-002'
            """
        ).fetchone()[0]

        self.assertEqual(
            audit_after,
            self.initial_ai002_audit_count,
        )

    def test_ai002_repeat_execution_is_deterministic_and_audited(self):
        first = self.post_ai002(
            self.analyst_cookie,
            self.headers,
        )
        second = self.post_ai002(
            self.analyst_cookie,
            self.headers,
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

        self.assertEqual(
            first.json()["simulation"],
            second.json()["simulation"],
        )

        audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-002'
            """
        ).fetchone()[0]

        self.assertEqual(
            audit_count,
            self.initial_ai002_audit_count + 2,
        )

    def test_ai003_anonymous_user_is_rejected(self):
        response = self.post_ai003()
        self.assertEqual(response.status_code, 401)

    def test_ai003_auditor_without_execute_permission_is_rejected(self):
        response = self.post_ai003(
            self.auditor_cookie,
            self.headers,
        )
        self.assertEqual(response.status_code, 403)

    def test_ai003_execute_only_without_target_read_is_rejected(self):
        response = self.post_ai003(
            {"sentinel_session": "execute-only-test-session"},
            self.headers,
        )
        self.assertEqual(response.status_code, 403)

    def test_ai003_missing_csrf_is_rejected(self):
        response = self.post_ai003(
            self.analyst_cookie,
            {"Origin": BASE_URL},
        )
        self.assertEqual(response.status_code, 403)

    def test_ai003_untrusted_origin_is_rejected(self):
        response = self.post_ai003(
            self.admin_cookie,
            {
                "Origin": "http://untrusted.invalid",
                "X-CSRF-Token": "test-csrf",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_ai003_analyst_can_execute_controlled_simulation(self):
        response = self.post_ai003(
            self.analyst_cookie,
            self.headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("cache-control"),
            "no-store",
        )

        body = response.json()
        result = body["simulation"]

        self.assertEqual(result["scenario_id"], "AI-003")
        self.assertEqual(
            result["scenario_name"],
            "Agent Tool Misuse & Permission Enforcement",
        )
        self.assertTrue(result["simulation_only"])
        self.assertFalse(result["persisted"])
        self.assertFalse(result["real_tools_invoked"])
        self.assertFalse(result["real_shell_used"])
        self.assertFalse(result["real_filesystem_accessed"])
        self.assertFalse(result["real_network_requests_sent"])
        self.assertFalse(result["real_accounts_modified"])
        self.assertEqual(result["attempt_count"], 4)
        self.assertEqual(result["blue_team_control"], "PASS")
        self.assertEqual(result["assessment_result"], "PASS")

        vulnerable = result["vulnerable_agent"]
        secure = result["secure_agent"]

        self.assertEqual(vulnerable["accepted_count"], 4)
        self.assertTrue(vulnerable["canary_exposed"])
        self.assertEqual(len(vulnerable["results"]), 4)
        self.assertTrue(
            all(item["accepted"] for item in vulnerable["results"])
        )

        self.assertEqual(secure["denied_count"], 4)
        self.assertFalse(secure["canary_exposed"])
        self.assertEqual(len(secure["results"]), 4)
        self.assertTrue(
            all(not item["accepted"] for item in secure["results"])
        )

        secure_rule_ids = {
            rule
            for item in secure["results"]
            for rule in item["detection_rules"]
        }
        self.assertTrue({
            "AGENT-TOOL-001",
            "AGENT-TOOL-002",
            "AGENT-TOOL-003",
            "AGENT-TOOL-004",
            "AGENT-ALLOWLIST-001",
            "AGENT-PERM-001",
        }.issubset(secure_rule_ids))

        self.assertTrue(body["audit_recorded"])
        self.assertFalse(body["assessment_created"])
        self.assertFalse(body["test_run_created"])
        self.assertFalse(body["finding_created"])
        self.assertFalse(body["evidence_persisted"])

        audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-003'
            """
        ).fetchone()[0]
        self.assertEqual(
            audit_count,
            self.initial_ai003_audit_count + 1,
        )

        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM assessments").fetchone()[0],
            self.initial_assessments,
        )
        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM test_runs").fetchone()[0],
            self.initial_runs,
        )
        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            self.initial_findings,
        )
        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            self.initial_evidence,
        )
        self.assertEqual(
            self.memory.execute("SELECT COUNT(*) FROM security_events").fetchone()[0],
            self.initial_security_events,
        )
        self.assertTrue(
            all(
                row["is_enabled"] == 0
                for row in self.memory.execute(
                    "SELECT is_enabled FROM target_profiles"
                )
            )
        )

    def test_ai003_enabled_target_is_rejected_without_audit(self):
        self.memory.execute(
            """
            UPDATE target_profiles
            SET is_enabled = 1
            WHERE id = ?
            """,
            ("target-testgpt-secure-v1",),
        )
        self.memory.commit()

        response = self.post_ai003(
            self.analyst_cookie,
            self.headers,
        )
        self.assertEqual(response.status_code, 409)

        audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-003'
            """
        ).fetchone()[0]
        self.assertEqual(
            audit_count,
            self.initial_ai003_audit_count,
        )

    def test_ai003_repeat_execution_is_deterministic_and_audited(self):
        first = self.post_ai003(
            self.analyst_cookie,
            self.headers,
        )
        second = self.post_ai003(
            self.analyst_cookie,
            self.headers,
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            first.json()["simulation"],
            second.json()["simulation"],
        )

        audit_count = self.memory.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action = 'ai_security.simulation.executed'
              AND resource_id = 'AI-003'
            """
        ).fetchone()[0]
        self.assertEqual(
            audit_count,
            self.initial_ai003_audit_count + 2,
        )

    def test_ai003_client_cannot_replace_fixed_scenario(self):
        response = self.client.post(
            ENDPOINT_AI003,
            cookies=self.analyst_cookie,
            headers=self.headers,
            json={
                "scenario_id": "attacker-controlled",
                "attempts": [
                    {
                        "tool_name": "arbitrary.real.tool",
                        "required_permission": "admin",
                    }
                ],
            },
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()["simulation"]
        self.assertEqual(result["scenario_id"], "AI-003")
        self.assertEqual(result["attempt_count"], 4)
        self.assertEqual(result["secure_agent"]["denied_count"], 4)


    def test_in_memory_database_integrity(self):
        self.assertEqual(
            self.memory.execute("PRAGMA integrity_check").fetchone()[0],
            "ok",
        )
        self.assertEqual(
            self.memory.execute("PRAGMA foreign_key_check").fetchall(),
            [],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)