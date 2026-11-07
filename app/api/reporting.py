"""Sanitized assessment report construction.

Only explicitly allowlisted fields are returned to API consumers.
Raw execution output and synthetic content are never included.
"""

import re


SUPPORTED_SCENARIOS = frozenset({
    "AI-001",
    "AI-002",
    "AI-003",
    "AI-004",
})

RULE_ID_PATTERN = re.compile(r"[A-Z0-9][A-Z0-9_-]{0,63}\Z")

REPORT_LIMITATIONS = {
    "AI-001": [
        "Rule-based training demonstration, not a general semantic detector.",
        "Does not establish production security.",
    ],
    "AI-002": [
        "Fixed synthetic RAG demonstration without a real retrieval system.",
        "Does not provide comprehensive indirect injection protection.",
        "Does not establish production security.",
    ],
    "AI-003": [
        "Fixed deterministic synthetic tool requests only.",
        "Mock agents do not invoke real tools or external services.",
        "Does not establish production agent security.",
    ],
    "AI-004": [
        "Fixed synthetic memory entries only.",
        "Memory persists only across two interactions in one process.",
        "No real personal memory or external memory store is accessed.",
        "Demonstration cryptographic keys and local provenance rules are not production key management.",
        "Does not establish production security.",
    ],
}


def _mapping(value, field):
    if not isinstance(value, dict):
        raise ValueError(f"Invalid report structure: {field}")
    return value


def _boolean(record, field):
    value = record.get(field)

    if type(value) is not bool:
        raise ValueError(f"Invalid report boolean: {field}")

    return value


def _count(record, field, maximum=100000):
    value = record.get(field)

    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"Invalid report count: {field}")

    return value


def _rule_ids(record, field):
    value = record.get(field)

    if not isinstance(value, (list, tuple)):
        raise ValueError(f"Invalid report rule list: {field}")

    if len(value) > 32:
        raise ValueError(f"Report rule list exceeds limit: {field}")

    result = []

    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"Invalid report rule identifier: {field}")

        if not RULE_ID_PATTERN.fullmatch(item):
            raise ValueError(f"Invalid report rule identifier: {field}")

        result.append(item)

    return sorted(set(result))


def _metadata_text(record, field, maximum, nullable=False):
    value = record.get(field)

    if value is None and nullable:
        return None

    if not isinstance(value, str):
        raise ValueError(f"Invalid report metadata: {field}")

    if not value or len(value) > maximum:
        raise ValueError(f"Invalid report metadata length: {field}")

    return value


def _status(record, field):
    value = record.get(field)

    allowed = {
        "draft",
        "queued",
        "running",
        "completed",
        "failed",
        "cancelled",
    }

    if value not in allowed:
        raise ValueError(f"Invalid report status: {field}")

    return value


def _target_comparison(target, include_untrusted=False):
    target = _mapping(target, "target")

    result = {
        "blocked": _boolean(target, "blocked"),
        "control_triggered": _boolean(
            target,
            "control_triggered",
        ),
        "canary_disclosed": _boolean(
            target,
            "synthetic_disclosure_detected",
        ),
    }

    if include_untrusted:
        result["document_treated_as_untrusted"] = _boolean(
            target,
            "retrieved_document_treated_as_untrusted",
        )

    return result


def _agent_execution_count(agent, expected_count):
    agent = _mapping(agent, "agent")

    results = agent.get("results")

    if not isinstance(results, list):
        raise ValueError("Invalid agent result collection.")

    if len(results) != expected_count:
        raise ValueError("Unexpected agent result count.")

    return sum(
        _boolean(_mapping(item, "agent result"), "execution_performed")
        for item in results
    )


def build_assessment_report(
    *,
    assessment,
    test_run,
    scenario_code,
    scenario_name,
    execution_record,
):
    """Construct a new, sanitized report from a stored execution record."""

    if scenario_code not in SUPPORTED_SCENARIOS:
        raise ValueError("Unsupported report scenario.")

    assessment = _mapping(assessment, "assessment metadata")
    test_run = _mapping(test_run, "test-run metadata")
    execution_record = _mapping(
        execution_record,
        "execution record",
    )

    if type(execution_record.get("schema_version")) is not int:
        raise ValueError("Unsupported execution schema.")

    if execution_record["schema_version"] != 1:
        raise ValueError("Unsupported execution schema.")

    if execution_record.get("scenario_id") != scenario_code:
        raise ValueError("Execution scenario mismatch.")

    simulation = _mapping(
        execution_record.get("simulation"),
        "simulation",
    )

    if simulation.get("scenario_id") != scenario_code:
        raise ValueError("Simulation scenario mismatch.")

    if _boolean(simulation, "simulation_only") is not True:
        raise ValueError("Non-simulation execution is not supported.")

    scenario_name = (
        scenario_name
        if isinstance(scenario_name, str)
        and 0 < len(scenario_name) <= 160
        else None
    )

    if scenario_name is None:
        raise ValueError("Invalid scenario metadata.")

    assessment_status = _status(
        assessment,
        "assessment_status",
    )

    test_run_status = _status(
        test_run,
        "test_run_status",
    )

    assessment_metadata = {
        "assessment_id": _metadata_text(
            assessment, "assessment_id", 128
        ),
        "name": _metadata_text(
            assessment, "name", 200
        ),
        "status": assessment_status,
        "created_at": _metadata_text(
            assessment, "created_at", 64
        ),
        "started_at": _metadata_text(
            assessment, "started_at", 64, nullable=True
        ),
        "completed_at": _metadata_text(
            assessment, "completed_at", 64, nullable=True
        ),
    }

    test_run_metadata = {
        "test_run_id": _metadata_text(
            test_run, "test_run_id", 128
        ),
        "status": test_run_status,
        "started_at": _metadata_text(
            test_run, "started_at", 64, nullable=True
        ),
        "completed_at": _metadata_text(
            test_run, "completed_at", 64, nullable=True
        ),
    }

    comparison = {}
    metrics = {}

    if scenario_code in ("AI-001", "AI-002"):
        evaluation = _mapping(
            simulation.get("evaluation"),
            "evaluation",
        )

        vulnerable = _mapping(
            simulation.get("vulnerable_target"),
            "vulnerable_target",
        )

        secure = _mapping(
            simulation.get("secure_target"),
            "secure_target",
        )

        include_untrusted = scenario_code == "AI-002"

        comparison = {
            "vulnerable": _target_comparison(vulnerable),
            "secure": _target_comparison(
                secure,
                include_untrusted=include_untrusted,
            ),
        }

        if scenario_code == "AI-001":
            metrics = {
                "injection_signature_detected": _boolean(
                    evaluation,
                    "injection_signature_detected",
                ),
                "detection_rule_ids": _rule_ids(
                    secure,
                    "detection_rule_ids",
                ),
            }

        else:
            inspection = _mapping(
                simulation.get("document_inspection"),
                "document_inspection",
            )

            metrics = {
                "indirect_injection_detected": _boolean(
                    evaluation,
                    "indirect_injection_detected",
                ),
                "retrieved_document_content_returned": _boolean(
                    simulation,
                    "retrieved_document_content_returned",
                ),
                "document_detection_rule_ids": _rule_ids(
                    inspection,
                    "rule_ids",
                ),
            }

        control_result = evaluation.get("blue_team_control")

    elif scenario_code == "AI-003":
        vulnerable = _mapping(
            simulation.get("vulnerable_agent"),
            "vulnerable_agent",
        )

        secure = _mapping(
            simulation.get("secure_agent"),
            "secure_agent",
        )

        attempt_count = _count(
            simulation,
            "attempt_count",
            maximum=100,
        )

        comparison = {
            "vulnerable": {
                "accepted_count": _count(
                    vulnerable,
                    "accepted_count",
                    maximum=attempt_count,
                ),
                "canary_disclosed": _boolean(
                    vulnerable,
                    "canary_exposed",
                ),
                "execution_performed_count": (
                    _agent_execution_count(
                        vulnerable,
                        attempt_count,
                    )
                ),
            },
            "secure": {
                "denied_count": _count(
                    secure,
                    "denied_count",
                    maximum=attempt_count,
                ),
                "canary_disclosed": _boolean(
                    secure,
                    "canary_exposed",
                ),
                "execution_performed_count": (
                    _agent_execution_count(
                        secure,
                        attempt_count,
                    )
                ),
            },
        }

        metrics = {
            "attempt_count": attempt_count,
            "real_tools_invoked": _boolean(
                simulation,
                "real_tools_invoked",
            ),
        }

        control_result = simulation.get("blue_team_control")

        if simulation.get("assessment_result") != control_result:
            raise ValueError("AI-003 evaluation mismatch.")

    else:
        evaluation = _mapping(
            simulation.get("evaluation"),
            "evaluation",
        )

        vulnerable = _mapping(
            simulation.get("vulnerable_agent"),
            "vulnerable_agent",
        )

        secure = _mapping(
            simulation.get("secure_agent"),
            "secure_agent",
        )

        comparison = {}

        for label, agent in (
            ("vulnerable", vulnerable),
            ("secure", secure),
        ):
            comparison[label] = {
                "stored_count": _count(agent, "stored_count"),
                "quarantined_count": _count(
                    agent,
                    "quarantined_count",
                ),
                "retrieved_count": _count(
                    agent,
                    "retrieved_count",
                ),
                "persistent_instructions_followed": _count(
                    agent,
                    "persistent_instructions_followed",
                ),
                "canary_disclosed": _boolean(
                    agent,
                    "canary_exposed",
                ),
            }

        metrics = {
            "interaction_count": _count(
                simulation,
                "interaction_count",
                maximum=100,
            ),
            "memory_entry_count": _count(
                simulation,
                "memory_entry_count",
                maximum=100,
            ),
        }

        evaluation_fields = (
            "persistent_instruction_detected",
            "untrusted_provenance_detected",
            "benign_source_attestation_valid",
            "untrusted_source_attestation_valid",
            "tampered_memory_detected",
            "trusted_benign_memory_preserved",
            "poisoned_memory_quarantined",
            "tampered_memory_quarantined",
            "vulnerable_agent_followed_persistent_instruction",
            "secure_agent_followed_persistent_instruction",
            "vulnerable_agent_disclosed_canary",
            "secure_agent_disclosed_canary",
        )

        for field in evaluation_fields:
            metrics[field] = _boolean(evaluation, field)

        control_result = evaluation.get("blue_team_control")

    if control_result not in ("PASS", "FAIL"):
        raise ValueError("Invalid security-control result.")

    return {
        "report_schema_version": 1,
        "assessment": assessment_metadata,
        "test_run": test_run_metadata,
        "scenario": {
            "code": scenario_code,
            "name": scenario_name,
        },
        "summary": {
            "blue_team_control": control_result,
        },
        "comparison": comparison,
        "metrics": metrics,
        "scope": {
            "simulation_only": True,
        },
        "limitations": list(
            REPORT_LIMITATIONS[scenario_code]
        ),
    }


__all__ = [
    "SUPPORTED_SCENARIOS",
    "REPORT_LIMITATIONS",
    "build_assessment_report",
]