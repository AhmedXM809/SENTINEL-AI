"""Reusable, deterministic security policy evaluation.

This module produces authorization decisions only.
It never executes tools or performs operating-system actions.
"""

from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final


class RiskLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyOutcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class ToolPolicy:
    """Static authorization policy for a registered tool."""

    tool_name: str
    required_permission: str
    risk_level: RiskLevel
    enabled: bool
    requires_human_approval: bool


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable result of a policy evaluation."""

    tool_name: str
    outcome: PolicyOutcome
    risk_level: RiskLevel
    reason_code: str
    required_permission: str | None
    approval_required: bool
    matched_controls: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        """True only when the policy explicitly allows the request."""
        return self.outcome is PolicyOutcome.ALLOW

    @property
    def execution_performed(self) -> bool:
        """This policy engine never executes tools."""
        return False


_APPROVAL_REQUIRED_RISKS: Final = frozenset({
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
})


# The registry is immutable. Registering a tool does not implement
# its executor; it only defines how authorization requests are evaluated.
TOOL_POLICIES: Final = MappingProxyType({
    "record.read_public": ToolPolicy(
        tool_name="record.read_public",
        required_permission="records.public.read",
        risk_level=RiskLevel.LOW,
        enabled=True,
        requires_human_approval=False,
    ),
    "record.read_sensitive": ToolPolicy(
        tool_name="record.read_sensitive",
        required_permission="records.sensitive.read",
        risk_level=RiskLevel.HIGH,
        enabled=True,
        requires_human_approval=True,
    ),
    "network.request": ToolPolicy(
        tool_name="network.request",
        required_permission="network.external.request",
        risk_level=RiskLevel.HIGH,
        enabled=True,
        requires_human_approval=True,
    ),
    "command.execute": ToolPolicy(
        tool_name="command.execute",
        required_permission="commands.execute",
        risk_level=RiskLevel.CRITICAL,
        enabled=False,
        requires_human_approval=True,
    ),
    "access_control.modify": ToolPolicy(
        tool_name="access_control.modify",
        required_permission="access_control.modify",
        risk_level=RiskLevel.CRITICAL,
        enabled=False,
        requires_human_approval=True,
    ),
})


def evaluate_tool_request(
    tool_name: str,
    user_permissions: AbstractSet[str],
) -> PolicyDecision:
    """Evaluate a tool request without executing it.

    Unknown tools, disabled tools and missing permissions are denied.
    Medium-, high- and critical-risk tools require human approval.
    Only explicitly enabled, authorized, low-risk tools can receive ALLOW.
    """

    if (
        not isinstance(tool_name, str)
        or not tool_name
        or tool_name != tool_name.strip()
    ):
        raise ValueError("A valid, exact tool name is required.")

    if (
        not isinstance(user_permissions, AbstractSet)
        or isinstance(user_permissions, (str, bytes))
    ):
        raise TypeError("Permissions must be supplied as a set or frozenset.")

    if any(
        not isinstance(permission, str)
        or not permission
        or permission != permission.strip()
        for permission in user_permissions
    ):
        raise ValueError("Permission identifiers must be valid strings.")

    policy = TOOL_POLICIES.get(tool_name)

    if policy is None:
        return PolicyDecision(
            tool_name=tool_name,
            outcome=PolicyOutcome.DENY,
            risk_level=RiskLevel.UNKNOWN,
            reason_code="UNKNOWN_TOOL",
            required_permission=None,
            approval_required=False,
            matched_controls=("POLICY-DENY-DEFAULT-001",),
        )

    if not policy.enabled:
        return PolicyDecision(
            tool_name=tool_name,
            outcome=PolicyOutcome.DENY,
            risk_level=policy.risk_level,
            reason_code="TOOL_DISABLED",
            required_permission=policy.required_permission,
            approval_required=False,
            matched_controls=(
                "POLICY-TOOL-REGISTRY-001",
                "POLICY-TOOL-DISABLED-001",
            ),
        )

    if policy.required_permission not in user_permissions:
        return PolicyDecision(
            tool_name=tool_name,
            outcome=PolicyOutcome.DENY,
            risk_level=policy.risk_level,
            reason_code="PERMISSION_MISSING",
            required_permission=policy.required_permission,
            approval_required=False,
            matched_controls=("POLICY-PERMISSION-001",),
        )

    approval_required = (
        policy.requires_human_approval
        or policy.risk_level in _APPROVAL_REQUIRED_RISKS
    )

    if approval_required:
        return PolicyDecision(
            tool_name=tool_name,
            outcome=PolicyOutcome.REQUIRE_APPROVAL,
            risk_level=policy.risk_level,
            reason_code="HUMAN_APPROVAL_REQUIRED",
            required_permission=policy.required_permission,
            approval_required=True,
            matched_controls=(
                "POLICY-ALLOWLIST-001",
                "POLICY-PERMISSION-001",
                "POLICY-HUMAN-APPROVAL-001",
            ),
        )

    return PolicyDecision(
        tool_name=tool_name,
        outcome=PolicyOutcome.ALLOW,
        risk_level=policy.risk_level,
        reason_code="AUTHORIZED_LOW_RISK",
        required_permission=policy.required_permission,
        approval_required=False,
        matched_controls=(
            "POLICY-ALLOWLIST-001",
            "POLICY-PERMISSION-001",
            "POLICY-LOW-RISK-001",
        ),
    )