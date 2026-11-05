import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "app" / "web" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "app" / "web" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "app" / "web" / "styles.css").read_text(encoding="utf-8")
API = (ROOT / "app" / "api" / "assessments.py").read_text(encoding="utf-8")


class TestAI004FrontendContract(unittest.TestCase):
    def test_scenario_card_and_button_exist(self):
        self.assertIn(
            "AI Agent Memory Poisoning &amp; Persistent Instruction Manipulation",
            HTML,
        )
        self.assertIn('id="run-ai004-button"', HTML)
        self.assertIn("Two synthetic interactions", HTML)
        self.assertIn("SYNTHETIC MEMORY BOUNDARY", HTML)
        self.assertIn("Client-supplied memory entries", HTML)

    def test_result_elements_exist_and_are_unique(self):
        required = (
            "ai004-results",
            "ai004-overall-status",
            "ai004-execution-type",
            "ai004-interaction-count",
            "ai004-memory-count",
            "ai004-audit-status",
            "ai004-vulnerable-state",
            "ai004-vulnerable-storage",
            "ai004-vulnerable-followed",
            "ai004-vulnerable-canary",
            "ai004-vulnerable-details",
            "ai004-secure-state",
            "ai004-secure-storage",
            "ai004-secure-retrieved",
            "ai004-secure-canary",
            "ai004-secure-details",
            "ai004-injection-status",
            "ai004-provenance-status",
            "ai004-attestation-status",
            "ai004-integrity-status",
            "ai004-benign-status",
            "ai004-poisoned-status",
            "ai004-tampered-status",
            "ai004-persistence-status",
            "ai004-canary-status",
            "ai004-side-effects-status",
            "ai004-controls-status",
            "ai004-limitations",
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
            r'<section id="ai004-results" class="assessment-results" hidden aria-live="polite">',
        )

    def test_api_route_matches_frontend_path(self):
        self.assertIn('@router.post("/simulations/AI-004/run")', API)
        self.assertIn('"/api/v1/simulations/AI-004/run"', JS)

    def test_handler_requires_confirmation_permissions_and_csrf(self):
        start = JS.index("async function runAI004()")
        end = JS.index('byId("run-ai004-button").addEventListener', start)
        handler = JS[start:end]

        self.assertIn("window.confirm(", handler)
        self.assertIn("csrf: true", handler)
        self.assertIn('method: "POST"', handler)
        self.assertIn('permissions.includes("assessments.execute")', handler)
        self.assertIn('permissions.includes("targets.read")', handler)
        self.assertIn("body: {}", handler)

    def test_renderer_validates_memory_security_outcomes(self):
        required = (
            'result.scenario_id !== "AI-004"',
            "persistent_instruction_detected",
            "untrusted_provenance_detected",
            "benign_source_attestation_valid",
            "untrusted_source_attestation_valid",
            "tampered_memory_detected",
            "trusted_benign_memory_preserved",
            "poisoned_memory_quarantined",
            "tampered_memory_quarantined",
            "secure_agent_followed_persistent_instruction",
            "secure_agent_disclosed_canary",
            "result.real_memory_accessed === false",
            "result.real_filesystem_accessed === false",
            "result.real_network_requests_sent === false",
            "result.real_accounts_modified === false",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, JS)

        self.assertIn('const overall = byId("ai004-overall-status")', JS)
        self.assertIn("overall.textContent = passed", JS)
        self.assertIn('byId("ai004-controls-status").textContent', JS)

    def test_untrusted_values_are_rendered_as_text(self):
        self.assertIn(
            'byId("ai004-vulnerable-details").textContent',
            JS,
        )
        self.assertIn(
            'byId("ai004-secure-details").textContent',
            JS,
        )
        self.assertNotIn("innerHTML", JS)
        self.assertNotIn("insertAdjacentHTML", JS)
        self.assertNotIn("SENTINEL-AI004-SYNTHETIC-MEMORY-CANARY", HTML + JS)

    def test_no_inline_html_event_handlers(self):
        self.assertIsNone(
            re.search(
                r'\son(?:click|submit|load|error)\s*=',
                HTML,
                flags=re.IGNORECASE,
            )
        )

    def test_ai004_styles_are_present_and_responsive(self):
        self.assertIn("/* AI-004 memory poisoning workspace */", CSS)
        self.assertIn(".ai004-boundary-note", CSS)
        self.assertIn(".ai004-memory-output", CSS)
        self.assertIn(".ai004-evaluation-grid", CSS)
        self.assertIn("@media (max-width: 460px)", CSS)

    def test_footer_lists_all_four_scenarios(self):
        self.assertIn(
            "AI-001 + AI-002 + AI-003 + AI-004 / DETERMINISTIC TRAINING",
            HTML,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
