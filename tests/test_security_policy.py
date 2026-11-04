import unittest
from dataclasses import FrozenInstanceError

from app.core.security_policy import (
    PolicyOutcome,
    RiskLevel,
    TOOL_POLICIES,
    evaluate_tool_request,
)


class SecurityPolicyTests(unittest.TestCase):

    def test_explicitly_authorized_public_tool_is_allowed(self):
        result = evaluate_tool_request(
            "record.read_public",
            frozenset({"records.public.read"}),
        )

        self.assertEqual(result.outcome, PolicyOutcome.ALLOW)
        self.assertTrue(result.allowed)
        self.assertFalse(result.approval_required)
        self.assertEqual(result.risk_level, RiskLevel.LOW)
        self.assertEqual(result.reason_code, "AUTHORIZED_LOW_RISK")
        self.assertIn(
            "POLICY-ALLOWLIST-001",
            result.matched_controls,
        )

    def test_unknown_tool_is_denied_by_default(self):
        result = evaluate_tool_request(
            "unknown.tool",
            frozenset({"some.permission"}),
        )

        self.assertEqual(result.outcome, PolicyOutcome.DENY)
        self.assertEqual(result.risk_level, RiskLevel.UNKNOWN)
        self.assertEqual(result.reason_code, "UNKNOWN_TOOL")
        self.assertIn(
            "POLICY-DENY-DEFAULT-001",
            result.matched_controls,
        )

    def test_disabled_critical_tools_are_denied(self):
        disabled_tools = (
            "command.execute",
            "access_control.modify",
        )

        for tool_name in disabled_tools:
            with self.subTest(tool=tool_name):
                required = TOOL_POLICIES[tool_name].required_permission

                result = evaluate_tool_request(
                    tool_name,
                    frozenset({required}),
                )

                self.assertEqual(result.outcome, PolicyOutcome.DENY)
                self.assertEqual(result.reason_code, "TOOL_DISABLED")
                self.assertFalse(result.allowed)

    def test_missing_permission_is_denied(self):
        result = evaluate_tool_request(
            "record.read_public",
            frozenset(),
        )

        self.assertEqual(result.outcome, PolicyOutcome.DENY)
        self.assertEqual(result.reason_code, "PERMISSION_MISSING")
        self.assertFalse(result.approval_required)

    def test_sensitive_record_access_requires_human_approval(self):
        result = evaluate_tool_request(
            "record.read_sensitive",
            frozenset({"records.sensitive.read"}),
        )

        self.assertEqual(
            result.outcome,
            PolicyOutcome.REQUIRE_APPROVAL,
        )
        self.assertTrue(result.approval_required)
        self.assertFalse(result.allowed)
        self.assertEqual(result.risk_level, RiskLevel.HIGH)

    def test_external_network_request_requires_approval(self):
        result = evaluate_tool_request(
            "network.request",
            frozenset({"network.external.request"}),
        )

        self.assertEqual(
            result.outcome,
            PolicyOutcome.REQUIRE_APPROVAL,
        )
        self.assertTrue(result.approval_required)
        self.assertFalse(result.allowed)

    def test_approval_does_not_replace_permission(self):
        result = evaluate_tool_request(
            "record.read_sensitive",
            frozenset(),
        )

        self.assertEqual(result.outcome, PolicyOutcome.DENY)
        self.assertEqual(result.reason_code, "PERMISSION_MISSING")
        self.assertFalse(result.approval_required)

    def test_all_decisions_perform_no_real_execution(self):
        cases = (
            ("record.read_public", frozenset({"records.public.read"})),
            ("record.read_sensitive", frozenset({"records.sensitive.read"})),
            ("command.execute", frozenset({"commands.execute"})),
            ("unknown.tool", frozenset()),
        )

        for tool_name, permissions in cases:
            with self.subTest(tool=tool_name):
                result = evaluate_tool_request(tool_name, permissions)
                self.assertFalse(result.execution_performed)

    def test_permission_matching_is_exact(self):
        result = evaluate_tool_request(
            "record.read_public",
            frozenset({"Records.Public.Read"}),
        )

        self.assertEqual(result.outcome, PolicyOutcome.DENY)
        self.assertEqual(result.reason_code, "PERMISSION_MISSING")

    def test_policy_registry_is_immutable(self):
        with self.assertRaises(TypeError):
            TOOL_POLICIES["malicious.tool"] = TOOL_POLICIES["record.read_public"]

    def test_policy_decision_is_immutable(self):
        result = evaluate_tool_request(
            "record.read_public",
            frozenset({"records.public.read"}),
        )

        with self.assertRaises(FrozenInstanceError):
            result.reason_code = "MODIFIED"

    def test_string_permissions_are_rejected(self):
        with self.assertRaises(TypeError):
            evaluate_tool_request(
                "record.read_public",
                "records.public.read",
            )

    def test_list_permissions_are_rejected(self):
        with self.assertRaises(TypeError):
            evaluate_tool_request(
                "record.read_public",
                ["records.public.read"],
            )

    def test_empty_tool_name_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_tool_request("", frozenset())

    def test_whitespace_padded_tool_name_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_tool_request(
                " record.read_public ",
                frozenset({"records.public.read"}),
            )

    def test_invalid_permission_identifier_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_tool_request(
                "record.read_public",
                frozenset({" "}),
            )


if __name__ == "__main__":
    unittest.main()