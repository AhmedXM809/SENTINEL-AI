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
            'const canCreateAssessments = permissions.includes("assessments.create");',
            JS,
        )
        self.assertIn(
            'const canExecuteAssessments = permissions.includes("assessments.execute")',
            JS,
        )
        self.assertIn(
            'const canAccessAssessments = canCreateAssessments || canExecuteAssessments;',
            JS,
        )
        self.assertIn(
            'byId("assessments-nav").hidden = !canAccessAssessments;',
            JS,
        )
        self.assertIn(
            'byId("assessment-draft-panel").hidden = !canCreateAssessments;',
            JS,
        )
        self.assertIn(
            'card.hidden = !canExecuteAssessments;',
            JS,
        )
        self.assertEqual(
            JS.count('!permissions.includes("assessments.execute")'),
            4,
        )

    def test_draft_creation_uses_create_permission_and_csrf_protected_post(self):
        self.assertIn(
            'if (!permissions.includes("assessments.create"))',
            JS,
        )
        self.assertIn(
            'apiRequest("/api/v1/assessments", {',
            JS,
        )
        self.assertIn('method: "POST",', JS)
        self.assertIn('csrf: true,', JS)
        self.assertIn('scenario_codes: scenarioCodes', JS)
        self.assertIn('data.execution_started === false', JS)

        self.assertIn('id="draft-assessment-form"', HTML)
        self.assertIn('id="assessment-draft-panel"', HTML)

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


    def test_report_panel_exists_once_and_starts_hidden(self):
        self.assertRegex(
            HTML,
            r'<section\s+id="assessment-report-panel"[\s\S]*?\shidden\s*>',
        )

        required_ids = (
            "history-list-view",
            "assessment-report-panel",
            "report-back-button",
            "report-feedback",
            "report-loading",
            "report-content",
            "report-scenario-title",
            "report-assessment-id",
            "report-result-description",
            "report-result-status",
            "report-metadata-grid",
            "report-comparison-grid",
            "report-metrics-grid",
            "report-limitations",
            "report-scope-note",
        )

        for element_id in required_ids:
            with self.subTest(element_id=element_id):
                self.assertEqual(
                    len(re.findall(
                        rf'id="{re.escape(element_id)}"',
                        HTML,
                    )),
                    1,
                )

    def test_history_list_and_report_panel_are_separate(self):
        history_section = HTML.index(
            'id="assessment-history-page"'
        )
        list_wrapper = HTML.index(
            'id="history-list-view"'
        )
        history_heading = HTML.index(
            '<div class="targets-page-heading">',
            history_section,
        )
        report_opening = re.search(
            r'<section\s+id="assessment-report-panel"',
            HTML,
        )
        self.assertIsNotNone(report_opening)

        self.assertLess(history_section, list_wrapper)
        self.assertLess(list_wrapper, history_heading)
        self.assertLess(history_heading, report_opening.start())

        before_report = HTML[:report_opening.start()].rstrip()
        self.assertTrue(before_report.endswith("</div>"))

    def test_history_table_has_report_action_column(self):
        self.assertEqual(
            HTML.count('<th scope="col">Report</th>'),
            1,
        )

        self.assertIn(
            'reportButton.textContent = reportAvailable ? "View report" : "Report pending";',
            JS,
        )
        self.assertIn(
            "reportButton.dataset.assessmentId = reportId;",
            JS,
        )


    def test_history_report_action_requires_completed_assessment_and_run(self):
        self.assertIn(
            'item.assessment_status === "completed"',
            JS,
        )
        self.assertIn(
            'item.test_run_status === "completed"',
            JS,
        )
        self.assertIn(
            'reportButton.disabled = !reportId || reportId.length > 128 || !reportAvailable;',
            JS,
        )
        self.assertIn(
            'reportButton.textContent = reportAvailable ? "View report" : "Report pending";',
            JS,
        )

    def test_report_api_uses_encoded_id_and_read_only_request(self):
        self.assertIn(
            '`/api/v1/assessments/${encodeURIComponent(safeId)}/report`',
            JS,
        )
        self.assertIn('cache: "no-store"', JS)
        self.assertIn(
            'byId("history-table-body").addEventListener("click"',
            JS,
        )

    def test_four_scenario_comparison_allowlists_exist(self):
        self.assertIn("const REPORT_COMPARISON_LABELS = {", JS)
        self.assertIn("const REPORT_METRIC_LABELS = {", JS)

        for scenario in ("AI-001", "AI-002", "AI-003", "AI-004"):
            with self.subTest(scenario=scenario):
                self.assertIn(f'"{scenario}": {{', JS)

        for field in (
            "document_treated_as_untrusted",
            "accepted_count",
            "denied_count",
            "execution_performed_count",
            "quarantined_count",
            "persistent_instructions_followed",
            "trusted_benign_memory_preserved",
        ):
            with self.subTest(field=field):
                self.assertIn(field, JS)

    def test_report_renderer_validates_schema_and_scenario(self):
        self.assertIn(
            "function renderAssessmentReport(data)",
            JS,
        )
        self.assertIn(
            "data.report_schema_version !== 1",
            JS,
        )
        self.assertIn(
            '["AI-001", "AI-002", "AI-003", "AI-004"].includes(data.scenario.code)',
            JS,
        )
        self.assertIn(
            "expectedFields.length !== actualFields.length",
            JS,
        )
        self.assertIn(
            "The scenario metrics contain unexpected fields.",
            JS,
        )

    def test_untrusted_report_content_uses_text_content(self):
        required_safe_rendering = (
            "heading.textContent = label;",
            "content.textContent = displayValue;",
            "item.textContent = limitation;",
            'byId("report-scenario-title").textContent',
            'byId("report-scope-note").textContent',
        )

        for expression in required_safe_rendering:
            with self.subTest(expression=expression):
                self.assertIn(expression, JS)

        self.assertNotIn("innerHTML", JS)
        self.assertNotIn("insertAdjacentHTML", JS)

    def test_report_loading_error_and_back_navigation_exist(self):
        self.assertIn("async function loadAssessmentReport(assessmentId)", JS)
        self.assertIn("function closeAssessmentReport()", JS)
        self.assertIn("assessmentReportRequest += 1;", JS)
        self.assertIn(
            'byId("report-loading").hidden = false;',
            JS,
        )
        self.assertIn(
            'byId("report-content").hidden = true;',
            JS,
        )
        self.assertIn(
            "Assessment report could not be loaded or validated.",
            JS,
        )
        self.assertIn(
            'byId("report-back-button").addEventListener("click"',
            JS,
        )

    def test_report_panel_respects_view_navigation(self):
        self.assertIn(
            'byId("assessment-report-panel").hidden = true;',
            JS,
        )
        self.assertIn(
            'byId("history-list-view").hidden = false;',
            JS,
        )
        self.assertIn(
            "activeAssessmentReportId !== safeId",
            JS,
        )

    def test_report_styles_support_responsive_and_accessible_layout(self):
        required_styles = (
            ".assessment-report-panel",
            ".report-result-banner",
            ".report-status-badge.pass",
            ".report-comparison-card.vulnerable",
            ".report-comparison-card.secure",
            ".report-metadata-grid",
            ".report-metrics-grid",
            ".report-limitations",
            ".history-view-report-button",
            ":focus-visible",
            "@media (max-width: 760px)",
            "@media (max-width: 520px)",
            "@media (prefers-reduced-motion: reduce)",
        )

        for selector in required_styles:
            with self.subTest(selector=selector):
                self.assertIn(selector, CSS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
