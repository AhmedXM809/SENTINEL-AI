import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "app" / "web" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "app" / "web" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "app" / "web" / "styles.css").read_text(encoding="utf-8")
API = (ROOT / "app" / "api" / "assessments.py").read_text(encoding="utf-8")


class TestAI001FrontendContract(unittest.TestCase):
    def test_assessments_navigation_and_page_exist(self):
        self.assertIn('id="assessments-nav"', HTML)
        self.assertIn('href="#assessments"', HTML)
        self.assertIn('id="assessments-page"', HTML)
        self.assertIn('id="assessments-module-card"', HTML)

    def test_result_elements_are_present_and_unique(self):
        required = (
            "assessment-results", "assessment-feedback", "ai001-overall-status",
            "ai001-vulnerable-output", "ai001-secure-output", "ai001-vulnerable-rules",
            "ai001-secure-rules", "ai001-controls-status", "ai001-limitations",
        )
        for element_id in required:
            with self.subTest(element_id=element_id):
                self.assertEqual(len(re.findall(rf'id="{re.escape(element_id)}"', HTML)), 1)

    def test_assessment_page_starts_hidden(self):
        self.assertRegex(HTML, r'<section id="assessments-page" class="assessments-page" hidden>')

    def test_simulation_uses_authenticated_csrf_api_request(self):
        self.assertIn('"/api/v1/simulations/AI-001/run"', JS)
        self.assertIn("csrf: true", JS)
        self.assertIn('method: "POST"', JS)
        self.assertIn("assessments.execute", JS)

    def test_assessments_navigation_requires_both_permissions(self):
        self.assertRegex(
            JS,
            r'const canExecuteAssessments = permissions\.includes\("assessments\.execute"\)\s+&& permissions\.includes\("targets\.read"\)',
        )
        self.assertRegex(
            JS,
            r'if\s*\(\s*!permissions\.includes\("assessments\.execute"\)\s*\|\|\s*!permissions\.includes\("targets\.read"\)',
        )
    def test_ai002_scenario_and_results_markup_exist(self):
        required = (
            "run-ai002-button",
            "ai002-results",
            "ai002-overall-status",
            "ai002-document-id",
            "ai002-inspection-rules",
            "ai002-vulnerable-output",
            "ai002-secure-output",
            "ai002-controls-status",
            "ai002-limitations",
        )
        for element_id in required:
            with self.subTest(element_id=element_id):
                self.assertEqual(
                    len(re.findall(rf'id="{re.escape(element_id)}"', HTML)),
                    1,
                )

    def test_ai002_result_panel_starts_hidden(self):
        self.assertRegex(
            HTML,
            r'<section id="ai002-results" class="assessment-results" hidden aria-live="polite">',
        )

    def test_ai002_api_route_matches_frontend_path(self):
        self.assertIn('@router.post("/simulations/AI-002/run")', API)
        self.assertIn('"/api/v1/simulations/AI-002/run"', JS)

    def test_ai002_run_handler_uses_csrf_confirmation_and_permissions(self):
        start = JS.index("async function runAI002()")
        end = JS.index('byId("run-ai002-button").addEventListener', start)
        handler = JS[start:end]
        self.assertIn("window.confirm(", handler)
        self.assertIn("csrf: true", handler)
        self.assertIn('method: "POST"', handler)
        self.assertIn('permissions.includes("assessments.execute")', handler)
        self.assertIn('permissions.includes("targets.read")', handler)

    def test_ai002_outputs_are_rendered_as_text(self):
        self.assertIn('byId("ai002-vulnerable-output").textContent', JS)
        self.assertIn('byId("ai002-secure-output").textContent', JS)
        self.assertIn('byId("ai002-inspection-rules").textContent', JS)
        self.assertNotIn("innerHTML", JS)
        self.assertNotIn("insertAdjacentHTML", JS)

    def test_ai002_raw_document_instruction_is_not_in_html(self):
        self.assertNotIn("UNTRUSTED DOCUMENT INSTRUCTION", HTML)
        self.assertIn("Document content is held inside the training engine", HTML)
    def test_user_confirmation_is_required(self):
        self.assertIn("window.confirm(", JS)
        self.assertIn('id="run-ai001-button"', HTML)

    def test_result_values_are_rendered_as_text(self):
        self.assertIn('byId("ai001-vulnerable-output").textContent', JS)
        self.assertIn('byId("ai001-secure-output").textContent', JS)
        self.assertNotIn("innerHTML", JS)
        self.assertNotIn("insertAdjacentHTML", JS)

    def test_html_has_no_inline_event_handlers(self):
        self.assertIsNone(re.search(r'\son(?:click|submit|load|error)\s*=', HTML, flags=re.IGNORECASE))

    def test_api_route_matches_frontend_path(self):
        self.assertIn('@router.post("/simulations/AI-001/run")', API)

    def test_assessment_styles_are_present(self):
        self.assertIn("/* AI-001 assessment workspace */", CSS)
        self.assertIn(".assessment-result-grid", CSS)
        self.assertIn(".simulation-output", CSS)


if __name__ == "__main__":
    unittest.main(verbosity=2)