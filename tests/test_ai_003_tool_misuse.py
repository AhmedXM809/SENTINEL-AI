import unittest

from app.core.ai003_tool_misuse import (
    SCENARIO_ATTEMPTS,
    SCENARIO_ID,
    SYNTHETIC_CANARY,
    DeterministicAgentTarget,
    ToolAttempt,
    run_ai_003,
)


class AI003ToolMisuseTests(unittest.TestCase):

    def setUp(self):
        self.secure_agent = DeterministicAgentTarget(
            target_type="secure",
            allowed_tools=frozenset({"record.read_public"}),
            permissions=frozenset({"records.public.read"}),
        )

        self.vulnerable_agent = DeterministicAgentTarget(
            target_type="vulnerable",
        )

    def test_scenario_identity(self):
        self.assertEqual(SCENARIO_ID, "AI-003")
        self.assertEqual(len(SCENARIO_ATTEMPTS), 4)

    def test_all_four_vulnerable_attempts_are_accepted(self):
        results = [
            self.vulnerable_agent.evaluate(attempt)
            for attempt in SCENARIO_ATTEMPTS
        ]

        self.assertEqual(len(results), 4)
        self.assertTrue(all(result.accepted for result in results))

    def test_all_four_secure_attempts_are_denied(self):
        results = [
            self.secure_agent.evaluate(attempt)
            for attempt in SCENARIO_ATTEMPTS
        ]

        self.assertEqual(len(results), 4)
        self.assertTrue(all(not result.accepted for result in results))

    def test_sensitive_record_canary_is_exposed_only_by_vulnerable_agent(self):
        sensitive_attempt = SCENARIO_ATTEMPTS[0]

        vulnerable_result = self.vulnerable_agent.evaluate(
            sensitive_attempt
        )
        secure_result = self.secure_agent.evaluate(
            sensitive_attempt
        )

        self.assertTrue(vulnerable_result.canary_exposed)
        self.assertIn(
            SYNTHETIC_CANARY,
            vulnerable_result.synthetic_response,
        )

        self.assertFalse(secure_result.canary_exposed)
        self.assertNotIn(
            SYNTHETIC_CANARY,
            secure_result.synthetic_response,
        )

    def test_secure_agent_reports_tool_and_permission_denials(self):
        for attempt in SCENARIO_ATTEMPTS:
            with self.subTest(tool=attempt.tool_name):
                result = self.secure_agent.evaluate(attempt)

                self.assertIn(
                    attempt.detection_rule,
                    result.detection_rules,
                )
                self.assertIn(
                    "AGENT-ALLOWLIST-001",
                    result.detection_rules,
                )
                self.assertIn(
                    "AGENT-PERM-001",
                    result.detection_rules,
                )

    def test_secure_agent_accepts_explicitly_allowed_tool(self):
        allowed_attempt = ToolAttempt(
            attempt_id="TEST-ALLOWED-001",
            tool_name="record.read_public",
            required_permission="records.public.read",
            detection_rule="TEST-ALLOW-001",
            description="Synthetic authorized public-record read.",
        )

        result = self.secure_agent.evaluate(allowed_attempt)

        self.assertTrue(result.accepted)
        self.assertEqual(result.decision, "ACCEPTED_AUTHORIZED")
        self.assertFalse(result.canary_exposed)
        self.assertEqual(result.detection_rules, ())

    def test_secure_agent_rejects_missing_permission(self):
        agent = DeterministicAgentTarget(
            target_type="secure",
            allowed_tools=frozenset({"record.read_public"}),
            permissions=frozenset(),
        )

        attempt = ToolAttempt(
            attempt_id="TEST-PERM-001",
            tool_name="record.read_public",
            required_permission="records.public.read",
            detection_rule="TEST-PERM-RULE",
            description="Synthetic permission test.",
        )

        result = agent.evaluate(attempt)

        self.assertFalse(result.accepted)
        self.assertIn("AGENT-PERM-001", result.detection_rules)

    def test_secure_agent_rejects_tool_not_on_allowlist(self):
        agent = DeterministicAgentTarget(
            target_type="secure",
            allowed_tools=frozenset(),
            permissions=frozenset({"records.public.read"}),
        )

        attempt = ToolAttempt(
            attempt_id="TEST-ALLOWLIST-001",
            tool_name="record.read_public",
            required_permission="records.public.read",
            detection_rule="TEST-ALLOWLIST-RULE",
            description="Synthetic allowlist test.",
        )

        result = agent.evaluate(attempt)

        self.assertFalse(result.accepted)
        self.assertIn(
            "AGENT-ALLOWLIST-001",
            result.detection_rules,
        )

    def test_unsupported_target_type_is_rejected(self):
        with self.assertRaises(ValueError):
            DeterministicAgentTarget(target_type="unknown")

    def test_full_simulation_passes(self):
        result = run_ai_003()

        self.assertEqual(result["scenario_id"], "AI-003")
        self.assertEqual(result["assessment_result"], "PASS")
        self.assertEqual(result["blue_team_control"], "PASS")
        self.assertEqual(result["attempt_count"], 4)
        self.assertEqual(
            result["vulnerable_agent"]["accepted_count"],
            4,
        )
        self.assertEqual(
            result["secure_agent"]["denied_count"],
            4,
        )

    def test_simulation_is_deterministic(self):
        first = run_ai_003()
        second = run_ai_003()

        self.assertEqual(first, second)

    def test_simulation_has_no_real_side_effects(self):
        result = run_ai_003()

        self.assertTrue(result["simulation_only"])
        self.assertFalse(result["persisted"])
        self.assertFalse(result["real_tools_invoked"])
        self.assertFalse(result["real_shell_used"])
        self.assertFalse(result["real_filesystem_accessed"])
        self.assertFalse(result["real_network_requests_sent"])
        self.assertFalse(result["real_accounts_modified"])

    def test_secure_results_never_contain_canary(self):
        result = run_ai_003()

        for item in result["secure_agent"]["results"]:
            self.assertFalse(item["canary_exposed"])
            self.assertNotIn(
                SYNTHETIC_CANARY,
                item["synthetic_response"],
            )


if __name__ == "__main__":
    unittest.main()