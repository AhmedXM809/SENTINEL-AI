"""Controlled AI security simulations with sanitized history persistence."""

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
from app.core.ai_security import (
    SYNTHETIC_CANARY as AI001_SYNTHETIC_CANARY,
    run_ai_001,
)
from app.core.ai002_indirect import (
    SYNTHETIC_RAG_CANARY,
    run_ai_002,
)
from app.core.ai003_tool_misuse import (
    SYNTHETIC_CANARY as AI003_SYNTHETIC_CANARY,
    run_ai_003,
)
from app.core.ai004_memory_poisoning import (
    SYNTHETIC_MEMORY_CANARY,
    run_ai_004,
)
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


def _redact_synthetic_canaries(value):
    """Recursively redact all four fixed synthetic canary values."""

    canaries = (
        AI001_SYNTHETIC_CANARY,
        SYNTHETIC_RAG_CANARY,
        AI003_SYNTHETIC_CANARY,
        SYNTHETIC_MEMORY_CANARY,
    )

    if isinstance(value, dict):
        return {
            _redact_synthetic_canaries(key):
            _redact_synthetic_canaries(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_redact_synthetic_canaries(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_synthetic_canaries(item) for item in value)

    if isinstance(value, str):
        for canary in canaries:
            value = value.replace(
                canary,
                "[REDACTED_SYNTHETIC_CANARY]",
            )
        return value

    return value


def _persist_simulation_history(
    connection,
    user_id: str,
    scenario_id: str,
    simulation_result: dict,
) -> dict:
    """Persist one completed assessment, test run, and audit event atomically."""

    scenario_records = {
        "AI-001": "test-case-ai-001",
        "AI-002": "test-case-ai-002",
        "AI-003": "test-case-ai-003",
        "AI-004": "test-case-ai-004",
    }

    test_case_id = scenario_records.get(scenario_id)
    if test_case_id is None:
        raise ValueError("Unsupported simulation scenario.")

    assessment_id = str(uuid4())
    test_run_id = str(uuid4())

    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    safe_result = _redact_synthetic_canaries(simulation_result)

    assessment_name = (
        f"{scenario_id} - "
        f"{safe_result.get('scenario_name', scenario_id)} "
        "(Vulnerable vs Secure)"
    )

    execution_record = {
        "schema_version": 1,
        "scenario_id": scenario_id,
        "target_profile_ids": [
            "target-testgpt-vulnerable-v1",
            "target-testgpt-secure-v1",
        ],
        "model_profile_id": "model-deterministic-mock-v1",
        "simulation": safe_result,
    }

    connection.execute(
        """
        INSERT INTO assessments (
            id,
            name,
            created_by,
            target_profile_id,
            model_profile_id,
            status,
            created_at,
            started_at,
            completed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            assessment_id,
            assessment_name,
            user_id,
            "target-testgpt-vulnerable-v1",
            "model-deterministic-mock-v1",
            "completed",
            now,
            now,
            now,
        ),
    )

    connection.execute(
        """
        INSERT INTO test_runs (
            id,
            assessment_id,
            test_case_id,
            status,
            started_at,
            completed_at,
            execution_result,
            error_summary
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            test_run_id,
            assessment_id,
            test_case_id,
            "completed",
            now,
            now,
            json.dumps(
                execution_record,
                ensure_ascii=False,
                sort_keys=True,
            ),
            None,
        ),
    )

    _audit_simulation(connection, user_id, scenario_id)

    return {
        "assessment_id": assessment_id,
        "test_run_id": test_run_id,
    }



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
    """Execute fixed AI-001 and persist its synthetic assessment history."""

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

            result = _redact_synthetic_canaries(result)
            history = _persist_simulation_history(
                connection,
                user.user_id,
                "AI-001",
                result,
            )

    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="The simulation history could not be saved.",
        ) from None

    return {
        "simulation": result,
        "audit_recorded": True,
        "history_persisted": True,
        "assessment_created": True,
        "test_run_created": True,
        "assessment_id": history["assessment_id"],
        "test_run_id": history["test_run_id"],
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
    """Execute fixed AI-002 and persist its synthetic assessment history."""

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
            result = run_ai_002()

            if result["evaluation"]["blue_team_control"] != "PASS":
                raise HTTPException(
                    status_code=500,
                    detail="The AI-002 defensive evaluation did not pass.",
                )

            result = _redact_synthetic_canaries(result)
            history = _persist_simulation_history(
                connection,
                user.user_id,
                "AI-002",
                result,
            )

    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="The simulation history could not be saved.",
        ) from None

    return {
        "simulation": result,
        "audit_recorded": True,
        "history_persisted": True,
        "assessment_created": True,
        "test_run_created": True,
        "assessment_id": history["assessment_id"],
        "test_run_id": history["test_run_id"],
        "finding_created": False,
        "evidence_persisted": False,
    }

@router.post("/simulations/AI-003/run")
def execute_ai_003(
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
    """Execute fixed AI-003 and persist its synthetic assessment history."""

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
            # Preserve the approved disabled-target and mock-model boundary.
            _verify_training_profiles(connection)

            # Fixed synthetic scenario; no request-supplied tools or arguments.
            result = run_ai_003()

            if result["blue_team_control"] != "PASS":
                raise HTTPException(
                    status_code=500,
                    detail="The AI-003 defensive evaluation did not pass.",
                )

            result = _redact_synthetic_canaries(result)
            history = _persist_simulation_history(
                connection,
                user.user_id,
                "AI-003",
                result,
            )

    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="The simulation history could not be saved.",
        ) from None

    return {
        "simulation": result,
        "audit_recorded": True,
        "history_persisted": True,
        "assessment_created": True,
        "test_run_created": True,
        "assessment_id": history["assessment_id"],
        "test_run_id": history["test_run_id"],
        "finding_created": False,
        "evidence_persisted": False,
    }



def _redact_ai004_canary(value):
    """Backward-compatible wrapper for the shared synthetic redactor."""

    return _redact_synthetic_canaries(value)

@router.post("/simulations/AI-004/run")
def execute_ai_004(
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
    """Execute fixed AI-004 and persist its synthetic assessment history."""

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
            # Preserve the established disabled-target and mock-model boundary.
            _verify_training_profiles(connection)

            # Fixed synthetic memory scenario; no caller-supplied memory.
            result = run_ai_004()

            if result["evaluation"]["blue_team_control"] != "PASS":
                raise HTTPException(
                    status_code=500,
                    detail="The AI-004 defensive evaluation did not pass.",
                )

            # Redact before either storage or API response.
            result = _redact_synthetic_canaries(result)

            history = _persist_simulation_history(
                connection,
                user.user_id,
                "AI-004",
                result,
            )

    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="The simulation history could not be saved.",
        ) from None

    return {
        "simulation": result,
        "audit_recorded": True,
        "history_persisted": True,
        "assessment_created": True,
        "test_run_created": True,
        "assessment_id": history["assessment_id"],
        "test_run_id": history["test_run_id"],
        "finding_created": False,
        "evidence_persisted": False,
    }
