import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.db.connection import get_connection
from app.authentication.routes import router as authentication_router
from app.api.targets import router as targets_router
from app.api.assessments import router as assessments_router

app = FastAPI(
    title="SENTINEL AI",
    description="AI Security Testing & Defense Platform",
    version="0.1.0",
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost"],
)
app.include_router(authentication_router)
app.include_router(targets_router)
app.include_router(assessments_router)


@app.get("/", tags=["System"], include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/app/", status_code=307)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "SENTINEL AI API",
    }


@app.get("/health/ready", tags=["System"])
def readiness() -> dict[str, str]:
    try:
        with get_connection() as connection:
            result = connection.execute(
                "SELECT 1"
            ).fetchone()

            foreign_keys = connection.execute(
                "PRAGMA foreign_keys"
            ).fetchone()[0]

            schema_version = connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]

            table_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'table'
                  AND name NOT LIKE 'sqlite_%'
                """
            ).fetchone()[0]

            if (
                result is None
                or result[0] != 1
                or foreign_keys != 1
                or schema_version not in (1, 2, 3, 4, 5)
                or table_count != (
                    19 if schema_version == 5
                    else 16 if schema_version in (3, 4)
                    else 15
                )
            ):
                raise HTTPException(
                    status_code=503,
                    detail="Database is not ready.",
                )

    except (sqlite3.Error, OSError):
        raise HTTPException(
            status_code=503,
            detail="Database is not ready.",
        ) from None

    return {
        "status": "ready",
        "service": "SENTINEL AI API",
        "database": "connected",
        "schema_version": str(schema_version),
        "tables": str(table_count),
        "foreign_keys": "enabled",
    }
@app.middleware("http")
async def add_web_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )

    if request.url.path == "/" or request.url.path.startswith("/app"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'",
        )

    return response


WEB_DIRECTORY = Path(__file__).resolve().parent / "web"

app.mount(
    "/app",
    StaticFiles(directory=str(WEB_DIRECTORY), html=True),
    name="web",
)