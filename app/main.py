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
from app.api.history import router as history_router

app = FastAPI(
    title="SENTINEL AI",
    description="AI Security Testing & Defense Platform",
    version="0.4.0",
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost"],
)
app.include_router(authentication_router)
app.include_router(targets_router)
app.include_router(assessments_router)
app.include_router(history_router)


@app.get("/", tags=["System"], include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/app/", status_code=307)


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "SENTINEL AI API",
    }


REQUIRED_TEST_CASES = {
    "test-case-ai-001": "AI-001",
    "test-case-ai-002": "AI-002",
    "test-case-ai-003": "AI-003",
    "test-case-ai-004": "AI-004",
}


@app.get("/health/ready", tags=["System"])
def readiness() -> dict[str, str]:
    try:
        with get_connection() as connection:
            result = connection.execute("SELECT 1").fetchone()

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

            registered_test_cases = {}

            if schema_version == 6:
                placeholders = ", ".join(
                    "?" for _ in REQUIRED_TEST_CASES
                )
                rows = connection.execute(
                    f"""
                    SELECT id, scenario_code, is_enabled
                    FROM test_cases
                    WHERE id IN ({placeholders})
                    """,
                    tuple(REQUIRED_TEST_CASES),
                ).fetchall()

                registered_test_cases = {
                    row["id"]: (
                        row["scenario_code"],
                        row["is_enabled"],
                    )
                    for row in rows
                }

            expected_test_cases = {
                case_id: (scenario_code, 1)
                for case_id, scenario_code in REQUIRED_TEST_CASES.items()
            }

            if (
                result is None
                or result[0] != 1
                or foreign_keys != 1
                or schema_version != 6
                or table_count != 19
                or registered_test_cases != expected_test_cases
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
        "registered_test_cases": str(len(registered_test_cases)),
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