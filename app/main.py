from fastapi import FastAPI

app = FastAPI(
    title="SENTINEL AI",
    description="AI Security Testing & Defense Platform",
    version="0.1.0",
)


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
