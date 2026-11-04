"""Controlled, non-persistent AI security simulations."""

import json
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
)

from app.authentication.routes import (
    SESSION_COOKIE_NAME,
    get_auth_service,
    require_same_origin,
    set_no_store,
)
from app.authentication.service import AuthenticatedUser, LoginService
from app.core.ai_security import run_ai_001
from app.db.connection import get_connection


router = APIRouter(
    prefix="/api/v1",
    tags=["AI Security Simulations"],
)


def get_simulation_user(
    session_token: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
    service: LoginService = Depends(get_auth_service),
) -> AuthenticatedUser:
    if not session_token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    user = service.get_current_user(session_token)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    return user


def require_execute_permission(user: AuthenticatedUser) -> None:
    required_permissions = {
        "assessments.execute",
        "targets.read",
    }

    if not required_permissions.issubset(user.permissions):
        raise HTTPException(
            status_code=403,
            detail="Assessment execution and target-read permissions are required.",
        )


def _audit_simulation(connection, user_id: str, scenario_id: str) -> None:
    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    connection.execute(
        """
        INSERT INTO audit_log (
            id,
            user_id,
            action,
            resource_type,
            resource_id,
            outcome,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid4()),
            user_id,
            "ai_security.simulation.executed",
            "simulation",
            scenario_id,
            "success",
            now,
        ),
    )


def _verify_training_profiles(connection) -> None:
    rows = connection.execute(
        """
        SELECT id, name, target_type, security_mode, is_enabled
        FROM target_profiles
        WHERE id IN (?, ?)
        ORDER BY id
        """,
        (
            "target-testgpt-vulnerable-v1",
            "target-testgpt-secure-v1",
        ),
    ).fetchall()

    expected = {
        "target-testgpt-vulnerable-v1": (
            "TestGPT-Vulnerable",
            "vulnerable",
            "controlled_vulnerable",
        ),
        "target-testgpt-secure-v1": (
            "TestGPT-Secure",
            "secure",
            "controlled_protected",
        ),
    }

    if len(rows) != 2:
        raise HTTPException(
            status_code=409,
            detail="The two standard isolated training profiles are required.",
        )

    for row in rows:
        expected_profile = expected.get(row["id"])

        if expected_profile is None:
            raise HTTPException(
                status_code=409,
                detail="Unexpected training profile configuration.",
            )

        actual = (
            row["name"],
            row["target_type"],
            row["security_mode"],
        )

        if actual != expected_profile or row["is_enabled"] != 0:
            raise HTTPException(
                status_code=409,
                detail="Training profiles must match the approved disabled configuration.",
            )

    model = connection.execute(
        """
        SELECT name, provider_type, model_identifier, configuration_json
        FROM model_profiles
        WHERE id = ?
        """,
        ("model-deterministic-mock-v1",),
    ).fetchone()

    if model is None:
        raise HTTPException(
            status_code=409,
            detail="The deterministic mock model profile is required.",
        )

    if (
        model["name"] != "Deterministic Mock Model v1"
        or model["provider_type"] != "deterministic_mock"
        or model["model_identifier"] != "sentinel-deterministic-v1"
    ):
        raise HTTPException(
            status_code=409,
            detail="The configured model is not the approved deterministic mock.",
        )

    try:
        configuration = json.loads(model["configuration_json"])
    except (TypeError, json.JSONDecodeError):
        raise HTTPException(
            status_code=409,
            detail="The deterministic mock configuration is invalid.",
        ) from None

    safe_configuration = (
        configuration.get("external_network") is False
        and configuration.get("filesystem_access") is False
        and configuration.get("shell_access") is False
        and configuration.get("synthetic_data_only") is True
    )

    if not safe_configuration:
        raise HTTPException(
            status_code=409,
            detail="The mock model does not satisfy the required isolation settings.",
        )


@router.post("/simulations/AI-001/run")
def execute_ai_001(
    request: Request,
    response: Response,
    session_token: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
    csrf_token: str | None = Header(
        default=None,
        alias="X-CSRF-Token",
    ),
    user: AuthenticatedUser = Depends(get_simulation_user),
    auth_service: LoginService = Depends(get_auth_service),
) -> dict:
    """Execute fixed AI-001 in memory; only its audit event is persisted."""

    require_same_origin(request)
    set_no_store(response)

    if (
        not session_token
        or not csrf_token
        or not auth_service.validate_csrf(
            session_token,
            csrf_token,
        )
    ):
        raise HTTPException(
            status_code=403,
            detail="CSRF validation failed.",
        )

    require_execute_permission(user)

    try:
        with get_connection() as connection:
            _verify_training_profiles(connection)

            # Fixed, in-code scenario: no caller-supplied prompt or target.
            result = run_ai_001()

            if result["evaluation"]["blue_team_control"] != "PASS":
                raise HTTPException(
                    status_code=500,
                    detail="The AI-001 defensive evaluation did not pass.",
                )

            # Record only the execution audit event.
            _audit_simulation(connection, user.user_id, "AI-001")

    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="The simulation could not access its local configuration.",
        ) from None

    return {
        "simulation": result,
        "audit_recorded": True,
        "assessment_created": False,
        "test_run_created": False,
        "finding_created": False,
        "evidence_persisted": False,
    }

@router.post("/simulations/AI-002/run")
def execute_ai_002(
    request: Request,
    response: Response,
    session_token: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
    csrf_token: str | None = Header(
        default=None,
        alias="X-CSRF-Token",
    ),
    user: AuthenticatedUser = Depends(get_simulation_user),
    auth_service: LoginService = Depends(get_auth_service),
) -> dict:
    """Execute fixed AI-002 in memory; only its audit event is persisted."""

    require_same_origin(request)
    set_no_store(response)

    if (
        not session_token
        or not csrf_token
        or not auth_service.validate_csrf(
            session_token,
            csrf_token,
        )
    ):
        raise HTTPException(
            status_code=403,
            detail="CSRF validation failed.",
        )

    require_execute_permission(user)

    try:
        with get_connection() as connection:
            # Reuse the exact approved disabled-target and mock-model
            # preflight used by AI-001.
            _verify_training_profiles(connection)

            # The document and query are fixed inside the engine.
            # No request-supplied document or prompt is accepted.
            from app.core.ai002_indirect import run_ai_002

            result = run_ai_002()

            if result["evaluation"]["blue_team_control"] != "PASS":
                raise HTTPException(
                    status_code=500,
                    detail="The AI-002 defensive evaluation did not pass.",
                )

            # Record only the scenario-specific audit event.
            _audit_simulation(
                connection,
                user.user_id,
                "AI-002",
            )

    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="The simulation could not access its local configuration.",
        ) from None

    return {
        "simulation": result,
        "audit_recorded": True,
        "assessment_created": False,
        "test_run_created": False,
        "finding_created": False,
        "evidence_persisted": False,
    }
