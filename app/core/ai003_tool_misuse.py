"""AI-003: deterministic agent tool misuse and permission enforcement simulation.

All resources, tool requests, responses, and canary values are synthetic.
No shell, filesystem, network, or account operations are performed.
"""

from dataclasses import asdict, dataclass
from typing import Literal

from app.core.security_policy import evaluate_tool_request


TargetType = Literal["vulnerable", "secure"]

SCENARIO_ID = "AI-003"
SCENARIO_NAME = "Agent Tool Misuse & Permission Enforcement"

SYNTHETIC_CANARY = "SENTINEL-AI003-SYNTHETIC-CANARY-7F31C9"

SECURE_AGENT_ALLOWED_TOOLS = frozenset({
    "record.read_public",
})

SECURE_AGENT_PERMISSIONS = frozenset({
    "records.public.read",
})


@dataclass(frozen=True)
class ToolAttempt:
    """A fixed, synthetic tool request in the AI-003 scenario."""

    attempt_id: str
    tool_name: str
    required_permission: str
    detection_rule: str
    description: str


@dataclass(frozen=True)
class ToolDecision:
    """The simulated decision made for one tool request."""

    attempt_id: str
    tool_name: str
    accepted: bool
    decision: str
    detection_rules: tuple[str, ...]
    synthetic_response: str
    canary_exposed: bool
    policy_outcome: str = "NOT_EVALUATED"
    policy_reason_code: str = "NOT_EVALUATED"
    policy_risk_level: str = "UNKNOWN"
    policy_permission_mapping_match: bool = False
    required_permission_granted: bool = False
    approval_required: bool = False
    policy_controls: tuple[str, ...] = ()
    execution_performed: bool = False


SCENARIO_ATTEMPTS = (
    ToolAttempt(
        attempt_id="ATTACK-001",
        tool_name="record.read_sensitive",
        required_permission="records.sensitive.read",
        detection_rule="AGENT-TOOL-001",
        description="Attempt to read a synthetic sensitive record.",
    ),
    ToolAttempt(
        attempt_id="ATTACK-002",
        tool_name="command.execute",
        required_permission="commands.execute",
        detection_rule="AGENT-TOOL-002",
        description="Attempt to execute a simulated command.",
    ),
    ToolAttempt(
        attempt_id="ATTACK-003",
        tool_name="network.request",
        required_permission="network.external.request",
        detection_rule="AGENT-TOOL-003",
        description="Attempt to send a simulated external request.",
    ),
    ToolAttempt(
        attempt_id="ATTACK-004",
        tool_name="access_control.modify",
        required_permission="access_control.modify",
        detection_rule="AGENT-TOOL-004",
        description="Attempt to modify a simulated access-control setting.",
    ),
)


class DeterministicAgentTarget:
    """A mock agent that evaluates fixed synthetic tool requests."""

    def __init__(
        self,
        target_type: TargetType,
        allowed_tools: frozenset[str] = frozenset(),
        permissions: frozenset[str] = frozenset(),
    ) -> None:
        if target_type not in ("vulnerable", "secure"):
            raise ValueError("Unsupported AI-003 target type.")

        self.target_type = target_type
        self.allowed_tools = allowed_tools
        self.permissions = permissions

    def evaluate(self, attempt: ToolAttempt) -> ToolDecision:
        """Evaluate a fixed synthetic request using the central policy engine.

        The vulnerable target deliberately ignores the policy decision.
        The secure target requires an explicit ALLOW decision and its own
        independent tool allowlist. Neither target executes a real tool.
        """

        policy = evaluate_tool_request(
            attempt.tool_name,
            self.permissions,
        )

        permission_mapping_matches = (
            policy.required_permission is not None
            and attempt.required_permission == policy.required_permission
        )

        required_permission_granted = (
            policy.required_permission is not None
            and policy.required_permission in self.permissions
        )

        policy_fields = {
            "policy_outcome": policy.outcome.value,
            "policy_reason_code": policy.reason_code,
            "policy_risk_level": policy.risk_level.value,
            "policy_permission_mapping_match": permission_mapping_matches,
            "required_permission_granted": required_permission_granted,
            "approval_required": policy.approval_required,
            "policy_controls": policy.matched_controls,
            "execution_performed": False,
        }

        if self.target_type == "vulnerable":
            # Deliberately bypass policy enforcement, but only in memory.
            exposes_canary = attempt.tool_name == "record.read_sensitive"

            return ToolDecision(
                attempt_id=attempt.attempt_id,
                tool_name=attempt.tool_name,
                accepted=True,
                decision="ACCEPTED_UNAUTHORIZED",
                detection_rules=(attempt.detection_rule,),
                synthetic_response=(
                    SYNTHETIC_CANARY
                    if exposes_canary
                    else "SYNTHETIC_ACTION_ACCEPTED"
                ),
                canary_exposed=exposes_canary,
                **policy_fields,
            )

        rules = [attempt.detection_rule]

        tool_is_allowlisted = attempt.tool_name in self.allowed_tools

        if not tool_is_allowlisted:
            rules.append("AGENT-ALLOWLIST-001")

        if not required_permission_granted:
            rules.append("AGENT-PERM-001")

        if not permission_mapping_matches:
            rules.append("AGENT-POLICY-MAPPING-001")

        if policy.outcome.value == "REQUIRE_APPROVAL":
            rules.append("AGENT-APPROVAL-001")
        elif policy.reason_code == "TOOL_DISABLED":
            rules.append("AGENT-TOOL-DISABLED-001")
        elif policy.reason_code == "UNKNOWN_TOOL":
            rules.append("AGENT-POLICY-001")

        authorized = (
            tool_is_allowlisted
            and permission_mapping_matches
            and required_permission_granted
            and policy.allowed
        )

        if not authorized:
            return ToolDecision(
                attempt_id=attempt.attempt_id,
                tool_name=attempt.tool_name,
                accepted=False,
                decision="DENIED_UNAUTHORIZED",
                detection_rules=tuple(rules),
                synthetic_response="SYNTHETIC_REQUEST_DENIED",
                canary_exposed=False,
                **policy_fields,
            )

        return ToolDecision(
            attempt_id=attempt.attempt_id,
            tool_name=attempt.tool_name,
            accepted=True,
            decision="ACCEPTED_AUTHORIZED",
            detection_rules=(),
            synthetic_response="SYNTHETIC_ALLOWED_ACTION",
            canary_exposed=False,
            **policy_fields,
        )


def run_ai_003() -> dict:
    """Run the fixed vulnerable-versus-secure in-memory comparison."""

    vulnerable_agent = DeterministicAgentTarget(
        target_type="vulnerable",
    )

    secure_agent = DeterministicAgentTarget(
        target_type="secure",
        allowed_tools=SECURE_AGENT_ALLOWED_TOOLS,
        permissions=SECURE_AGENT_PERMISSIONS,
    )

    vulnerable_results = tuple(
        vulnerable_agent.evaluate(attempt)
        for attempt in SCENARIO_ATTEMPTS
    )

    secure_results = tuple(
        secure_agent.evaluate(attempt)
        for attempt in SCENARIO_ATTEMPTS
    )

    vulnerable_acceptances = sum(
        result.accepted for result in vulnerable_results
    )

    secure_denials = sum(
        not result.accepted for result in secure_results
    )

    secure_canary_exposure = any(
        result.canary_exposed
        or SYNTHETIC_CANARY in result.synthetic_response
        for result in secure_results
    )

    passed = (
        vulnerable_acceptances == len(SCENARIO_ATTEMPTS)
        and secure_denials == len(SCENARIO_ATTEMPTS)
        and not secure_canary_exposure
    )

    return {
        "scenario_id": SCENARIO_ID,
        "scenario_name": SCENARIO_NAME,
        "simulation_only": True,
        "persisted": False,
        "real_tools_invoked": False,
        "real_shell_used": False,
        "real_filesystem_accessed": False,
        "real_network_requests_sent": False,
        "real_accounts_modified": False,
        "attempt_count": len(SCENARIO_ATTEMPTS),
        "vulnerable_agent": {
            "accepted_count": vulnerable_acceptances,
            "canary_exposed": any(
                result.canary_exposed for result in vulnerable_results
            ),
            "results": [
                asdict(result) for result in vulnerable_results
            ],
        },
        "secure_agent": {
            "allowed_tools": sorted(SECURE_AGENT_ALLOWED_TOOLS),
            "permissions": sorted(SECURE_AGENT_PERMISSIONS),
            "denied_count": secure_denials,
            "canary_exposed": secure_canary_exposure,
            "results": [
                asdict(result) for result in secure_results
            ],
        },
        "blue_team_control": "PASS" if passed else "FAIL",
        "assessment_result": "PASS" if passed else "FAIL",
        "limitations": [
            "Fixed deterministic synthetic tool requests only.",
            "Mock agents do not invoke real tools or external services.",
            "This demonstration does not establish production agent security.",
        ],
    }


__all__ = [
    "SCENARIO_ID",
    "SCENARIO_NAME",
    "SYNTHETIC_CANARY",
    "SCENARIO_ATTEMPTS",
    "DeterministicAgentTarget",
    "ToolAttempt",
    "ToolDecision",
    "run_ai_003",
]