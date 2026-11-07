import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "app" / "web" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "app" / "web" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "app" / "web" / "styles.css").read_text(encoding="utf-8")


class TestAssessmentHistoryFrontendContract(unittest.TestCase):

    def test_history_navigation_and_page_exist(self):
        self.assertIn('id="history-nav"', HTML)
        self.assertIn('href="#history"', HTML)
        self.assertIn('id="assessment-history-page"', HTML)

    def test_history_page_starts_hidden(self):
        self.assertRegex(
            HTML,
            r'<section id="assessment-history-page" class="assessment-history-page" hidden>',
        )

    def test_history_elements_exist_exactly_once(self):
        required_ids = (
            "history-refresh-button",
            "history-feedback",
            "history-total",
            "history-page-indicator",
            "history-table-body",
            "history-empty",
            "history-prev-button",
            "history-next-button",
        )

        for element_id in required_ids:
            with self.subTest(element_id=element_id):
                self.assertEqual(
                    len(re.findall(rf'id="{re.escape(element_id)}"', HTML)),
                    1,
                )

    def test_history_navigation_uses_read_permission(self):
        self.assertIn(
            'const canReadAssessmentHistory = permissions.includes("assessments.read");',
            JS,
        )
        self.assertIn(
            'byId("history-nav").hidden = !canReadAssessmentHistory;',
            JS,
        )
        self.assertIn(
            'selectedView === "history" && !canReadAssessmentHistory',
            JS,
        )

    def test_assessment_execution_permission_remains_separate(self):
        self.assertIn(
            'permissions.includes("assessments.execute")',
            JS,
        )
        self.assertIn(
            'const canExecuteAssessments = permissions.includes("assessments.execute")',
            JS,
        )
        self.assertIn(
            'byId("assessments-nav").hidden = !canExecuteAssessments;',
            JS,
        )

    def test_history_loader_calls_paginated_read_only_api(self):
        self.assertIn("ASSESSMENT_HISTORY_PAGE_SIZE = 10", JS)
        self.assertIn("loadAssessmentHistory", JS)
        self.assertIn("renderAssessmentHistory(data)", JS)
        self.assertIn(
            "`/api/v1/assessments?${query.toString()}`",
            JS,
        )
        self.assertIn('cache: "no-store"', JS)

    def test_untrusted_history_fields_use_text_rendering(self):
        self.assertIn(
            "name.textContent = historyText(item.name, item.assessment_id);",
            JS,
        )
        self.assertIn(
            "recordId.textContent = historyText(item.assessment_id);",
            JS,
        )
        self.assertIn(
            "scenarioName.textContent = historyText(item.scenario_name);",
            JS,
        )
        self.assertIn(
            "badge.textContent = historyText(value, \"Unknown\");",
            JS,
        )
        self.assertNotIn("innerHTML", JS)
        self.assertNotIn("insertAdjacentHTML", JS)

    def test_history_pagination_controls_are_bound(self):
        self.assertIn('byId("history-prev-button").addEventListener("click"', JS)
        self.assertIn('byId("history-next-button").addEventListener("click"', JS)
        self.assertIn('byId("history-refresh-button").addEventListener("click"', JS)

    def test_history_styles_are_responsive(self):
        self.assertIn("/* Assessment history explorer */", CSS)
        self.assertIn(".history-table-wrap", CSS)
        self.assertIn(".history-status.completed", CSS)
        self.assertIn("@media (max-width: 760px)", CSS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
