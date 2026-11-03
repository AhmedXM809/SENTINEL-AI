import os
from urllib.parse import urlsplit

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
)
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.authentication.service import (
    AuthenticationConfigurationError,
    AuthenticationFailed,
    LoginRateLimited,
    LoginService,
    MFAChallengeRequired,
)
from app.authentication.sessions import SESSION_LIFETIME_MINUTES
from app.authentication.mfa_flows import (
    MFAService,
    MFA_CHALLENGE_LIFETIME_SECONDS,
    MFAEnrollmentConflict,
    MFAEnrollmentFailed,
    MFAFlowAuthenticationFailed,
    MFAFlowConfigurationError,
    MFAFlowRateLimited,
)


SESSION_COOKIE_NAME = "sentinel_session"
SESSION_COOKIE_MAX_AGE = SESSION_LIFETIME_MINUTES * 60

MFA_CHALLENGE_COOKIE_NAME = "sentinel_mfa_challenge"
MFA_CHALLENGE_COOKIE_PATH = "/api/v1/auth/mfa"
MFA_CHALLENGE_COOKIE_MAX_AGE = MFA_CHALLENGE_LIFETIME_SECONDS

secure_setting = os.getenv(
    "SENTINEL_COOKIE_SECURE", "false"
).strip().casefold()

if secure_setting not in {"true", "false"}:
    raise RuntimeError("SENTINEL_COOKIE_SECURE must be true or false.")

COOKIE_SECURE = secure_setting == "true"

DEFAULT_ORIGINS = {
    "http://127.0.0.1:8000",
    "http://localhost:8000",
}


def load_allowed_origins() -> frozenset[str]:
    configured = os.getenv("SENTINEL_ALLOWED_ORIGINS")

    origins = (
        DEFAULT_ORIGINS
        if configured is None
        else {
            item.strip().rstrip("/")
            for item in configured.split(",")
            if item.strip()
        }
    )

    if not origins:
        raise RuntimeError("No allowed authentication origins configured.")

    for origin in origins:
        parsed = urlsplit(origin)

        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise RuntimeError("Invalid authentication origin configuration.")

        hostname = (parsed.hostname or "").casefold()

        if COOKIE_SECURE:
            if parsed.scheme != "https":
                raise RuntimeError("Secure cookies require HTTPS origins.")
        elif (
            parsed.scheme != "http"
            or hostname not in {"127.0.0.1", "localhost"}
        ):
            raise RuntimeError(
                "Non-secure cookies are restricted to local HTTP origins."
            )

    return frozenset(origins)


ALLOWED_ORIGINS = load_allowed_origins()

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

_auth_service = LoginService()
_mfa_service = MFAService()


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: SecretStr


class MFAEnrollmentStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: SecretStr


class MFAEnrollmentConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(pattern=r"^[0-9]{6}$")


class MFAVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=6, max_length=64)


def get_auth_service() -> LoginService:
    return _auth_service


def get_mfa_service() -> MFAService:
    return _mfa_service


def require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")

    if origin not in ALLOWED_ORIGINS:
        raise HTTPException(
            status_code=403,
            detail="Request origin is not allowed.",
        )

    parsed = urlsplit(origin)
    request_host = request.headers.get("host", "")

    if parsed.netloc.casefold() != request_host.casefold():
        raise HTTPException(
            status_code=403,
            detail="Request origin is not allowed.",
        )


def set_no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_COOKIE_MAX_AGE,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )


def set_mfa_challenge_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=MFA_CHALLENGE_COOKIE_NAME,
        value=token,
        max_age=MFA_CHALLENGE_COOKIE_MAX_AGE,
        path=MFA_CHALLENGE_COOKIE_PATH,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )


def clear_mfa_challenge_cookie(response: Response) -> None:
    response.delete_cookie(
        key=MFA_CHALLENGE_COOKIE_NAME,
        path=MFA_CHALLENGE_COOKIE_PATH,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )


def require_session_and_csrf(
    session_token: str | None,
    csrf_token: str | None,
    service: LoginService,
) -> None:
    if not session_token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    if not csrf_token or not service.validate_csrf(
        session_token,
        csrf_token,
    ):
        raise HTTPException(
            status_code=403,
            detail="CSRF validation failed.",
        )

    if service.get_current_user(session_token) is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )


@router.post("/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    service: LoginService = Depends(get_auth_service),
) -> dict:
    require_same_origin(request)

    try:
        result = service.login(
            payload.username,
            payload.password.get_secret_value(),
        )

    except AuthenticationFailed:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        ) from None

    except LoginRateLimited as exc:
        raise HTTPException(
            status_code=429,
            detail="Authentication temporarily unavailable.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from None

    except AuthenticationConfigurationError:
        raise HTTPException(
            status_code=503,
            detail="Authentication service is unavailable.",
        ) from None

    set_no_store(response)

    if isinstance(result, MFAChallengeRequired):
        response.status_code = 202

        set_mfa_challenge_cookie(
            response,
            result.challenge_token,
        )

        # Do not expose the raw MFA challenge token in JSON.
        return {
            "mfa_required": True,
            "expires_at": result.expires_at,
            "next_step": "mfa_verification",
        }

    set_session_cookie(response, result.session_token)

    return {
        "authenticated": True,
        "user": {
            "id": result.user_id,
            "username": result.username,
        },
        "csrf_token": result.csrf_token,
        "expires_at": result.expires_at,
    }


@router.post("/mfa/verify")
def verify_mfa(
    payload: MFAVerifyRequest,
    request: Request,
    response: Response,
    challenge_token: str | None = Cookie(
        default=None,
        alias=MFA_CHALLENGE_COOKIE_NAME,
    ),
    service: MFAService = Depends(get_mfa_service),
) -> dict:
    require_same_origin(request)
    set_no_store(response)

    if not challenge_token:
        raise HTTPException(
            status_code=401,
            detail="MFA verification is required.",
        )

    try:
        result = service.complete_challenge(
            challenge_token,
            payload.code,
        )

    except MFAFlowAuthenticationFailed:
        raise HTTPException(
            status_code=401,
            detail="MFA verification failed.",
        ) from None

    except MFAFlowRateLimited as exc:
        raise HTTPException(
            status_code=429,
            detail="MFA verification temporarily delayed.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from None

    except MFAFlowConfigurationError:
        raise HTTPException(
            status_code=503,
            detail="MFA service is unavailable.",
        ) from None

    set_session_cookie(response, result.session_token)
    clear_mfa_challenge_cookie(response)

    return {
        "authenticated": True,
        "user": {
            "id": result.user_id,
            "username": result.username,
        },
        "csrf_token": result.csrf_token,
        "expires_at": result.expires_at,
    }


@router.post("/mfa/enroll")
def begin_mfa_enrollment(
    request: Request,
    payload: MFAEnrollmentStartRequest,
    response: Response,
    session_token: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
    csrf_token: str | None = Header(
        default=None,
        alias="X-CSRF-Token",
    ),
    auth_service: LoginService = Depends(get_auth_service),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> dict:
    require_same_origin(request)
    require_session_and_csrf(
        session_token,
        csrf_token,
        auth_service,
    )

    set_no_store(response)

    try:
        auth_service.verify_session_password(
            session_token,
            payload.password.get_secret_value(),
        )

    except AuthenticationFailed:
        raise HTTPException(
            status_code=401,
            detail="Password verification failed.",
        ) from None

    except LoginRateLimited as exc:
        raise HTTPException(
            status_code=429,
            detail="Password verification temporarily delayed.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from None

    except AuthenticationConfigurationError:
        raise HTTPException(
            status_code=503,
            detail="Authentication service is unavailable.",
        ) from None

    try:
        enrollment = mfa_service.start_enrollment(session_token)

    except MFAFlowAuthenticationFailed:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        ) from None

    except MFAEnrollmentConflict:
        raise HTTPException(
            status_code=409,
            detail="MFA is already enabled.",
        ) from None

    except MFAFlowConfigurationError:
        raise HTTPException(
            status_code=503,
            detail="MFA encryption is unavailable.",
        ) from None

    return {
        "enrollment_pending": True,
        "secret": enrollment.secret,
        "provisioning_uri": enrollment.provisioning_uri,
        "expires_at": enrollment.expires_at,
    }


@router.post("/mfa/enroll/confirm")
def confirm_mfa_enrollment(
    payload: MFAEnrollmentConfirmRequest,
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
    auth_service: LoginService = Depends(get_auth_service),
    mfa_service: MFAService = Depends(get_mfa_service),
) -> dict:
    require_same_origin(request)
    require_session_and_csrf(
        session_token,
        csrf_token,
        auth_service,
    )

    set_no_store(response)

    try:
        recovery_codes = mfa_service.confirm_enrollment(
            session_token,
            payload.code,
        )

    except MFAFlowAuthenticationFailed:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        ) from None

    except MFAEnrollmentFailed:
        raise HTTPException(
            status_code=400,
            detail="MFA enrollment confirmation failed.",
        ) from None

    except MFAFlowConfigurationError:
        raise HTTPException(
            status_code=503,
            detail="MFA service is unavailable.",
        ) from None

    # Enrollment revokes the prior sessions, including this one.
    clear_session_cookie(response)
    clear_mfa_challenge_cookie(response)

    # Recovery codes are returned once and never stored as plaintext.
    return {
        "mfa_enabled": True,
        "recovery_codes": list(recovery_codes),
        "recovery_codes_remaining": len(recovery_codes),
        "message": "Save these recovery codes securely. They will not be shown again.",
    }


@router.get("/me")
def current_user(
    response: Response,
    session_token: str | None = Cookie(
        default=None,
        alias=SESSION_COOKIE_NAME,
    ),
    service: LoginService = Depends(get_auth_service),
) -> dict:
    set_no_store(response)

    if not session_token:
        response.status_code = 401
        clear_session_cookie(response)
        return {"authenticated": False}

    user = service.get_current_user(session_token)

    if user is None:
        response.status_code = 401
        clear_session_cookie(response)
        return {"authenticated": False}

    try:
        csrf_token = service.issue_csrf_token(session_token)

    except AuthenticationConfigurationError:
        raise HTTPException(
            status_code=503,
            detail="Authentication service is unavailable.",
        ) from None

    return {
        "authenticated": True,
        "user": {
            "id": user.user_id,
            "username": user.username,
            "roles": list(user.roles),
            "permissions": sorted(user.permissions),
        },
        "csrf_token": csrf_token,
    }


@router.post("/logout")
def logout(
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
    service: LoginService = Depends(get_auth_service),
) -> dict:
    require_same_origin(request)
    set_no_store(response)

    if not session_token:
        clear_session_cookie(response)
        return {"authenticated": False}

    user = service.get_current_user(session_token)

    if user is None:
        clear_session_cookie(response)
        return {"authenticated": False}

    if not csrf_token or not service.validate_csrf(
        session_token,
        csrf_token,
    ):
        raise HTTPException(
            status_code=403,
            detail="CSRF validation failed.",
        )

    service.logout(session_token)
    clear_session_cookie(response)

    return {"authenticated": False}