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
from app.db.connection import get_connection


router = APIRouter(
    prefix="/api/v1",
    tags=["AI Targets"],
)


def authenticated_user(
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


def require_permission(
    user: AuthenticatedUser,
    permission: str,
) -> None:
    if permission not in user.permissions:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to perform this action.",
        )


def utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def write_audit_event(
    connection,
    *,
    user_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
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
            action,
            resource_type,
            resource_id,
            "success",
            created_at,
        ),
    )


@router.get("/targets")
def list_targets(
    response: Response,
    user: AuthenticatedUser = Depends(authenticated_user),
) -> dict:
    set_no_store(response)
    require_permission(user, "targets.read")

    try:
        with get_connection() as connection:
            target_rows = connection.execute(
                """
                SELECT
                    id,
                    name,
                    target_type,
                    security_mode,
                    is_enabled,
                    created_at
                FROM target_profiles
                ORDER BY target_type, name
                """
            ).fetchall()

            model_rows = (
                connection.execute(
                    """
                    SELECT
                        id,
                        name,
                        provider_type,
                        model_identifier,
                        created_at
                    FROM model_profiles
                    ORDER BY name
                    """
                ).fetchall()
                if "models.read" in user.permissions
                else []
            )

    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="Target information is temporarily unavailable.",
        ) from None

    return {
        "targets": [
            {
                "id": row["id"],
                "name": row["name"],
                "target_type": row["target_type"],
                "security_mode": row["security_mode"],
                "is_enabled": bool(row["is_enabled"]),
                "created_at": row["created_at"],
            }
            for row in target_rows
        ],
        "models": [
            {
                "id": row["id"],
                "name": row["name"],
                "provider_type": row["provider_type"],
                "model_identifier": row["model_identifier"],
                "created_at": row["created_at"],
            }
            for row in model_rows
        ],
    }


@router.post("/targets/initialize")
def initialize_standard_targets(
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
    user: AuthenticatedUser = Depends(authenticated_user),
    auth_service: LoginService = Depends(get_auth_service),
) -> dict:
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

    require_permission(user, "targets.manage")
    require_permission(user, "models.manage")

    now = utc_timestamp()

    standard_targets = (
        (
            "target-testgpt-vulnerable-v1",
            "TestGPT-Vulnerable",
            "vulnerable",
            "controlled_vulnerable",
        ),
        (
            "target-testgpt-secure-v1",
            "TestGPT-Secure",
            "secure",
            "controlled_protected",
        ),
    )

    model_configuration = json.dumps(
        {
            "external_network": False,
            "filesystem_access": False,
            "shell_access": False,
            "synthetic_data_only": True,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    model = (
        "model-deterministic-mock-v1",
        "Deterministic Mock Model v1",
        "deterministic_mock",
        "sentinel-deterministic-v1",
        model_configuration,
    )

    created_targets = 0
    created_models = 0

    try:
        with get_connection() as connection:

            # Idempotent creation: no existing profile is overwritten.
            for target in standard_targets:
                target_id, name, target_type, security_mode = target

                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO target_profiles (
                        id,
                        name,
                        target_type,
                        security_mode,
                        is_enabled,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, 0, ?)
                    """,
                    (
                        target_id,
                        name,
                        target_type,
                        security_mode,
                        now,
                    ),
                )

                row = connection.execute(
                    """
                    SELECT
                        id, name, target_type,
                        security_mode, is_enabled
                    FROM target_profiles
                    WHERE id = ?
                    """,
                    (target_id,),
                ).fetchone()

                expected = (
                    target_id,
                    name,
                    target_type,
                    security_mode,
                    0,
                )

                actual = (
                    tuple(row)
                    if row is not None
                    else None
                )

                if actual != expected:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "A standard target identifier conflicts "
                            "with an existing profile."
                        ),
                    )

                if cursor.rowcount == 1:
                    created_targets += 1
                    write_audit_event(
                        connection,
                        user_id=user.user_id,
                        action="targets.profile.created",
                        resource_type="target_profile",
                        resource_id=target_id,
                        created_at=now,
                    )

            # Deterministic mock only; no external provider.
            model_id, model_name, provider, identifier, config = model

            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO model_profiles (
                    id,
                    name,
                    provider_type,
                    model_identifier,
                    configuration_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    model_id,
                    model_name,
                    provider,
                    identifier,
                    config,
                    now,
                ),
            )

            model_row = connection.execute(
                """
                SELECT
                    id, name, provider_type,
                    model_identifier, configuration_json
                FROM model_profiles
                WHERE id = ?
                """,
                (model_id,),
            ).fetchone()

            expected_model = (
                model_id,
                model_name,
                provider,
                identifier,
                config,
            )

            if (
                model_row is None
                or tuple(model_row) != expected_model
            ):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "The standard mock-model identifier conflicts "
                        "with an existing model profile."
                    ),
                )

            if cursor.rowcount == 1:
                created_models += 1
                write_audit_event(
                    connection,
                    user_id=user.user_id,
                    action="models.profile.created",
                    resource_type="model_profile",
                    resource_id=model_id,
                    created_at=now,
                )

    except HTTPException:
        raise
    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="Standard targets could not be initialized.",
        ) from None

    return {
        "initialized": True,
        "created_targets": created_targets,
        "created_models": created_models,
        "targets_enabled": False,
        "external_model_provider": False,
        "message": (
            "Standard isolated profiles are ready. "
            "No tests were executed and no target was enabled."
        ),
    }