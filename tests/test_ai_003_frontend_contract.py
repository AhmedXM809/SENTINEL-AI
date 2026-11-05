import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "app" / "web" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "app" / "web" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "app" / "web" / "styles.css").read_text(encoding="utf-8")
API = (ROOT / "app" / "api" / "assessments.py").read_text(encoding="utf-8")


class TestAI003FrontendContract(unittest.TestCase):
    def test_scenario_card_and_button_exist(self):
        self.assertIn("Agent Tool Misuse &amp; Permission Enforcement", HTML)
        self.assertIn('id="run-ai003-button"', HTML)
        self.assertIn("Four fixed synthetic attempts", HTML)
        self.assertIn("No real shell, filesystem, network, or account operations", HTML)

    def test_result_elements_exist_and_are_unique(self):
        required = (
            "ai003-results",
            "ai003-overall-status",
            "ai003-execution-type",
            "ai003-attempt-count",
            "ai003-audit-status",
            "ai003-vulnerable-state",
            "ai003-vulnerable-accepted",
            "ai003-vulnerable-canary",
            "ai003-vulnerable-details",
            "ai003-secure-state",
            "ai003-secure-denied",
            "ai003-secure-canary",
            "ai003-secure-details",
            "ai003-allowlist-status",
            "ai003-permission-status",
            "ai003-real-operations-status",
            "ai003-controls-status",
            "ai003-limitations",
        )
        for element_id in required:
            with self.subTest(element_id=element_id):
                self.assertEqual(
                    len(re.findall(rf'id="{re.escape(element_id)}"', HTML)),
                    1,
                )

    def test_result_panel_starts_hidden(self):
        self.assertRegex(
            HTML,
            r'<section id="ai003-results" class="assessment-results" hidden aria-live="polite">',
        )

    def test_api_route_matches_frontend_path(self):
        self.assertIn('@router.post("/simulations/AI-003/run")', API)
        self.assertIn('"/api/v1/simulations/AI-003/run"', JS)

    def test_handler_requires_confirmation_permissions_and_csrf(self):
        start = JS.index("async function runAI003()")
        end = JS.index('byId("run-ai003-button").addEventListener', start)
        handler = JS[start:end]

        self.assertIn("window.confirm(", handler)
        self.assertIn("csrf: true", handler)
        self.assertIn('method: "POST"', handler)
        self.assertIn('permissions.includes("assessments.execute")', handler)
        self.assertIn('permissions.includes("targets.read")', handler)
        self.assertIn("body: {}", handler)

    def test_result_renderer_checks_authorization_controls(self):
        self.assertIn('result.scenario_id !== "AI-003"', JS)
        self.assertIn('secureRuleIds.includes("AGENT-ALLOWLIST-001")', JS)
        self.assertIn('secureRuleIds.includes("AGENT-PERM-001")', JS)
        self.assertIn('result.blue_team_control === "PASS"', JS)
        self.assertIn('byId("ai003-vulnerable-details").textContent', JS)
        self.assertIn('byId("ai003-secure-details").textContent', JS)

    def test_untrusted_values_are_rendered_as_text(self):
        self.assertNotIn("innerHTML", JS)
        self.assertNotIn("insertAdjacentHTML", JS)
        self.assertNotIn("SENTINEL-AI003-SYNTHETIC-CANARY-7F31C9", HTML)
        self.assertNotIn("SENTINEL-AI003-SYNTHETIC-CANARY-7F31C9", JS)

    def test_no_inline_html_event_handlers(self):
        self.assertIsNone(
            re.search(
                r'\son(?:click|submit|load|error)\s*=',
                HTML,
                flags=re.IGNORECASE,
            )
        )

    def test_policy_engine_summary_elements_exist_and_are_unique(self):
        required = (
            "ai003-policy-engine-status",
            "ai003-policy-engine-detail",
        )
        for element_id in required:
            with self.subTest(element_id=element_id):
                self.assertEqual(
                    len(re.findall(rf'id="{re.escape(element_id)}"', HTML)),
                    1,
                )

        self.assertIn("CENTRAL SECURITY POLICY ENGINE", HTML)
        self.assertIn('class="ai003-policy-summary"', HTML)

    def test_renderer_displays_all_policy_decision_fields(self):
        required_fields = (
            "policy_outcome",
            "policy_reason_code",
            "policy_risk_level",
            "policy_permission_mapping_match",
            "required_permission_granted",
            "approval_required",
            "execution_performed",
            "policy_controls",
        )
        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(field, JS)

    def test_policy_engine_summary_requires_complete_safe_decisions(self):
        self.assertIn('validPolicyOutcomes.has(item.policy_outcome)', JS)
        self.assertIn('item.policy_outcome === "DENY"', JS)
        self.assertIn('item.execution_performed === false', JS)
        self.assertIn("const policyContractValid", JS)
        self.assertIn("const policyEnforced", JS)
        self.assertIn('byId("ai003-policy-engine-status").textContent', JS)
        self.assertIn('byId("ai003-policy-engine-detail").textContent', JS)

    def test_policy_details_continue_to_use_text_rendering(self):
        self.assertIn(
            'byId("ai003-vulnerable-details").textContent',
            JS,
        )
        self.assertIn(
            'byId("ai003-secure-details").textContent',
            JS,
        )
        self.assertIn(
            'byId("ai003-policy-engine-detail").textContent',
            JS,
        )
        self.assertNotIn("innerHTML", JS)
        self.assertNotIn("insertAdjacentHTML", JS)

    def test_ai003_styles_are_present(self):
        self.assertIn("/* AI-003 agent tool authorization workspace */", CSS)
        self.assertIn(".ai003-boundary-note", CSS)
        self.assertIn(".ai003-attempt-output", CSS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
