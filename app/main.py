import sqlite3

from fastapi import FastAPI, HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.db.connection import get_connection
from app.authentication.routes import router as authentication_router

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


@app.get("/", tags=["System"])
async def root() -> dict[str, str]:
    return {
        "service": "SENTINEL AI API",
        "version": app.version,
        "message": "API is running.",
    }


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
                or schema_version not in (1, 2, 3, 4)
                or table_count != (16 if schema_version in (3, 4) else 15)
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