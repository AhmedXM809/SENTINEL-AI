import unittest

from app.core.ai003_tool_misuse import (
    DeterministicAgentTarget,
    SCENARIO_ATTEMPTS,
    SYNTHETIC_CANARY,
    ToolAttempt,
    run_ai_003,
)


class AI003PolicyIntegrationTests(unittest.TestCase):

    def test_authorized_public_tool_receives_policy_allow(self):
        agent = DeterministicAgentTarget(
            target_type="secure",
            allowed_tools=frozenset({"record.read_public"}),
            permissions=frozenset({"records.public.read"}),
        )

        attempt = ToolAttempt(
            attempt_id="POLICY-ALLOW-001",
            tool_name="record.read_public",
            required_permission="records.public.read",
            detection_rule="POLICY-ALLOW-RULE",
            description="Synthetic authorized public-record request.",
        )

        result = agent.evaluate(attempt)

        self.assertTrue(result.accepted)
        self.assertEqual(result.policy_outcome, "ALLOW")
        self.assertEqual(
            result.policy_reason_code,
            "AUTHORIZED_LOW_RISK",
        )
        self.assertTrue(result.policy_permission_mapping_match)
        self.assertTrue(result.required_permission_granted)
        self.assertFalse(result.approval_required)
        self.assertFalse(result.execution_performed)

    def test_approval_required_tools_are_never_accepted(self):
        cases = (
            (
                "record.read_sensitive",
                "records.sensitive.read",
            ),
            (
                "network.request",
                "network.external.request",
            ),
        )

        for tool_name, permission in cases:
            with self.subTest(tool=tool_name):
                agent = DeterministicAgentTarget(
                    target_type="secure",
                    allowed_tools=frozenset({tool_name}),
                    permissions=frozenset({permission}),
                )

                attempt = ToolAttempt(
                    attempt_id="POLICY-APPROVAL-001",
                    tool_name=tool_name,
                    required_permission=permission,
                    detection_rule="POLICY-APPROVAL-RULE",
                    description="Synthetic approval-required request.",
                )

                result = agent.evaluate(attempt)

                self.assertFalse(result.accepted)
                self.assertEqual(
                    result.policy_outcome,
                    "REQUIRE_APPROVAL",
                )
                self.assertEqual(
                    result.policy_reason_code,
                    "HUMAN_APPROVAL_REQUIRED",
                )
                self.assertTrue(result.approval_required)
                self.assertIn(
                    "AGENT-APPROVAL-001",
                    result.detection_rules,
                )
                self.assertFalse(result.execution_performed)

    def test_disabled_critical_tools_are_denied_even_with_permission(self):
        cases = (
            (
                "command.execute",
                "commands.execute",
            ),
            (
                "access_control.modify",
                "access_control.modify",
            ),
        )

        for tool_name, permission in cases:
            with self.subTest(tool=tool_name):
                agent = DeterministicAgentTarget(
                    target_type="secure",
                    allowed_tools=frozenset({tool_name}),
                    permissions=frozenset({permission}),
                )

                attempt = ToolAttempt(
                    attempt_id="POLICY-DISABLED-001",
                    tool_name=tool_name,
                    required_permission=permission,
                    detection_rule="POLICY-DISABLED-RULE",
                    description="Synthetic disabled-tool request.",
                )

                result = agent.evaluate(attempt)

                self.assertFalse(result.accepted)
                self.assertEqual(result.policy_outcome, "DENY")
                self.assertEqual(
                    result.policy_reason_code,
                    "TOOL_DISABLED",
                )
                self.assertIn(
                    "AGENT-TOOL-DISABLED-001",
                    result.detection_rules,
                )
                self.assertFalse(result.execution_performed)

    def test_secure_agent_rejects_permission_mapping_mismatch(self):
        agent = DeterministicAgentTarget(
            target_type="secure",
            allowed_tools=frozenset({"network.request"}),
            permissions=frozenset({
                "network.external.request",
            }),
        )

        attempt = ToolAttempt(
            attempt_id="POLICY-MAPPING-001",
            tool_name="network.request",
            required_permission="records.public.read",
            detection_rule="POLICY-MAPPING-RULE",
            description="Synthetic mismatched permission request.",
        )

        result = agent.evaluate(attempt)

        self.assertFalse(result.accepted)
        self.assertFalse(result.policy_permission_mapping_match)
        self.assertTrue(result.required_permission_granted)
        self.assertIn(
            "AGENT-POLICY-MAPPING-001",
            result.detection_rules,
        )
        self.assertFalse(result.execution_performed)

    def test_vulnerable_agent_demonstrates_policy_bypass(self):
        agent = DeterministicAgentTarget(
            target_type="vulnerable",
        )

        sensitive_attempt = SCENARIO_ATTEMPTS[0]
        result = agent.evaluate(sensitive_attempt)

        self.assertTrue(result.policy_permission_mapping_match)
        self.assertFalse(result.required_permission_granted)
        self.assertEqual(result.policy_outcome, "DENY")
        self.assertEqual(
            result.policy_reason_code,
            "PERMISSION_MISSING",
        )
        self.assertTrue(result.accepted)
        self.assertEqual(
            result.decision,
            "ACCEPTED_UNAUTHORIZED",
        )
        self.assertTrue(result.canary_exposed)
        self.assertIn(SYNTHETIC_CANARY, result.synthetic_response)
        self.assertFalse(result.execution_performed)

    def test_every_simulation_decision_declares_no_real_execution(self):
        result = run_ai_003()

        all_decisions = (
            result["vulnerable_agent"]["results"]
            + result["secure_agent"]["results"]
        )

        self.assertEqual(len(all_decisions), 8)

        for decision in all_decisions:
            with self.subTest(
                attempt=decision["attempt_id"],
                agent=decision["decision"],
            ):
                self.assertFalse(decision["execution_performed"])

        self.assertTrue(result["simulation_only"])
        self.assertFalse(result["real_tools_invoked"])
        self.assertFalse(result["real_shell_used"])
        self.assertFalse(result["real_filesystem_accessed"])
        self.assertFalse(result["real_network_requests_sent"])
        self.assertFalse(result["real_accounts_modified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
