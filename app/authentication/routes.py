import os
from urllib.parse import urlsplit

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.authentication.service import (
    AuthenticationConfigurationError,
    AuthenticationFailed,
    LoginRateLimited,
    LoginService,
)
from app.authentication.sessions import SESSION_LIFETIME_MINUTES

SESSION_COOKIE_NAME = "sentinel_session"
SESSION_COOKIE_MAX_AGE = SESSION_LIFETIME_MINUTES * 60

secure_setting = os.getenv("SENTINEL_COOKIE_SECURE", "false").strip().casefold()
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
        elif parsed.scheme != "http" or hostname not in {"127.0.0.1", "localhost"}:
            raise RuntimeError(
                "Non-secure cookies are restricted to local HTTP origins."
            )

    return frozenset(origins)


ALLOWED_ORIGINS = load_allowed_origins()
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
_auth_service = LoginService()


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: SecretStr


def get_auth_service() -> LoginService:
    return _auth_service


def require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")

    if origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")

    parsed = urlsplit(origin)
    host = request.headers.get("host", "")

    if parsed.netloc.casefold() != host.casefold():
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")


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

    set_session_cookie(response, result.session_token)
    set_no_store(response)

    return {
        "authenticated": True,
        "user": {
            "id": result.user_id,
            "username": result.username,
        },
        "csrf_token": result.csrf_token,
        "expires_at": result.expires_at,
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
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
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

    if not csrf_token or not service.validate_csrf(session_token, csrf_token):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")

    service.logout(session_token)
    clear_session_cookie(response)
    return {"authenticated": False}