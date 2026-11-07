"""Draft assessment creation without executing any security scenario."""

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

from app.api.assessments import (
    _verify_training_profiles,
    get_simulation_user,
)
from app.authentication.routes import (
    SESSION_COOKIE_NAME,
    get_auth_service,
    require_same_origin,
    set_no_store,
)
from app.authentication.service import AuthenticatedUser, LoginService
from app.db.connection import get_connection


router = APIRouter(
    prefix="/api/v1",
    tags=["Assessment Management"],
)

APPROVED_SCENARIOS = frozenset({
    "AI-001",
    "AI-002",
    "AI-003",
    "AI-004",
})


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _audit_assessment_created(
    connection,
    user_id: str,
    assessment_id: str,
    created_at: str,
) -> None:
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
            "assessment.created",
            "assessment",
            assessment_id,
            "success",
            created_at,
        ),
    )


@router.post("/assessments", status_code=201)
def create_assessment_draft(
    request: Request,
    response: Response,
    payload: dict,
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
    """Create a draft and queued scenario records; never execute simulations."""

    require_same_origin(request)
    set_no_store(response)

    if (
        not session_token
        or not csrf_token
        or not auth_service.validate_csrf(session_token, csrf_token)
    ):
        raise HTTPException(
            status_code=403,
            detail="CSRF validation failed.",
        )

    if "assessments.create" not in user.permissions:
        raise HTTPException(
            status_code=403,
            detail="Assessment creation permission is required.",
        )

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=422,
            detail="A JSON object is required.",
        )

    unexpected_fields = set(payload) - {"name", "scenario_codes"}
    if unexpected_fields:
        raise HTTPException(
            status_code=422,
            detail="The request contains unsupported fields.",
        )

    name = payload.get("name")
    if not isinstance(name, str):
        raise HTTPException(
            status_code=422,
            detail="Assessment name must be text.",
        )

    name = name.strip()
    if not 3 <= len(name) <= 120:
        raise HTTPException(
            status_code=422,
            detail="Assessment name must contain between 3 and 120 characters.",
        )

    scenario_codes = payload.get("scenario_codes")
    if (
        not isinstance(scenario_codes, list)
        or not 1 <= len(scenario_codes) <= len(APPROVED_SCENARIOS)
        or any(not isinstance(code, str) for code in scenario_codes)
    ):
        raise HTTPException(
            status_code=422,
            detail="Select between one and four approved scenarios.",
        )

    if len(set(scenario_codes)) != len(scenario_codes):
        raise HTTPException(
            status_code=422,
            detail="Duplicate scenario selections are not allowed.",
        )

    if any(code not in APPROVED_SCENARIOS for code in scenario_codes):
        raise HTTPException(
            status_code=422,
            detail="One or more selected scenarios are not approved.",
        )

    assessment_id = str(uuid4())
    created_at = _utc_timestamp()
    created_runs = []

    try:
        with get_connection() as connection:
            # Validate the exact existing disabled training pair and
            # deterministic mock configuration before creating records.
            _verify_training_profiles(connection)

            placeholders = ",".join("?" for _ in scenario_codes)
            rows = connection.execute(
                f"""
                SELECT id, scenario_code
                FROM test_cases
                WHERE scenario_code IN ({placeholders})
                  AND is_enabled = 1
                """,
                tuple(scenario_codes),
            ).fetchall()

            test_case_ids = {
                row[1]: row[0]
                for row in rows
            }

            if set(test_case_ids) != set(scenario_codes):
                raise HTTPException(
                    status_code=422,
                    detail="One or more selected scenarios are not currently enabled.",
                )

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
                    name,
                    user.user_id,
                    "target-testgpt-vulnerable-v1",
                    "model-deterministic-mock-v1",
                    "draft",
                    created_at,
                    None,
                    None,
                ),
            )

            for scenario_code in scenario_codes:
                test_run_id = str(uuid4())

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
                        test_case_ids[scenario_code],
                        "queued",
                        None,
                        None,
                        None,
                        None,
                    ),
                )

                created_runs.append({
                    "test_run_id": test_run_id,
                    "scenario_code": scenario_code,
                    "status": "queued",
                })

            _audit_assessment_created(
                connection,
                user.user_id,
                assessment_id,
                created_at,
            )

    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="The draft assessment could not be saved.",
        ) from None

    return {
        "assessment_id": assessment_id,
        "name": name,
        "status": "draft",
        "created_at": created_at,
        "scenario_codes": list(scenario_codes),
        "test_runs": created_runs,
        "execution_started": False,
        "audit_recorded": True,
    }