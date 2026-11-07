"""Read-only assessment history API."""

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.api.assessments import get_simulation_user
from app.authentication.routes import set_no_store
from app.authentication.service import AuthenticatedUser
from app.db.connection import get_connection


router = APIRouter(
    prefix="/api/v1",
    tags=["Assessment History"],
)


@router.get(
    "/assessments",
    summary="List assessment history",
    description=(
        "Return paginated assessment metadata for users with "
        "the assessments.read permission. Stored execution results "
        "are deliberately excluded."
    ),
)
def list_assessments(
    response: Response,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: AuthenticatedUser = Depends(get_simulation_user),
) -> dict:
    """List assessment summaries without modifying stored history."""

    set_no_store(response)

    if "assessments.read" not in user.permissions:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to read assessment history.",
        )

    try:
        with get_connection() as connection:
            total = connection.execute(
                "SELECT COUNT(*) FROM assessments"
            ).fetchone()[0]

            rows = connection.execute(
                """
                SELECT
                    a.id AS assessment_id,
                    a.name,
                    a.status AS assessment_status,
                    a.created_at,
                    a.started_at,
                    a.completed_at,

                    (
                        SELECT tc.scenario_code
                        FROM test_runs tr
                        JOIN test_cases tc ON tc.id = tr.test_case_id
                        WHERE tr.assessment_id = a.id
                        ORDER BY
                            COALESCE(tr.completed_at, tr.started_at, '') DESC,
                            tr.id DESC
                        LIMIT 1
                    ) AS scenario_code,

                    (
                        SELECT tc.name
                        FROM test_runs tr
                        JOIN test_cases tc ON tc.id = tr.test_case_id
                        WHERE tr.assessment_id = a.id
                        ORDER BY
                            COALESCE(tr.completed_at, tr.started_at, '') DESC,
                            tr.id DESC
                        LIMIT 1
                    ) AS scenario_name,

                    (
                        SELECT tr.id
                        FROM test_runs tr
                        WHERE tr.assessment_id = a.id
                        ORDER BY
                            COALESCE(tr.completed_at, tr.started_at, '') DESC,
                            tr.id DESC
                        LIMIT 1
                    ) AS test_run_id,

                    (
                        SELECT tr.status
                        FROM test_runs tr
                        WHERE tr.assessment_id = a.id
                        ORDER BY
                            COALESCE(tr.completed_at, tr.started_at, '') DESC,
                            tr.id DESC
                        LIMIT 1
                    ) AS test_run_status,

                    (
                        SELECT COUNT(*)
                        FROM test_runs tr
                        WHERE tr.assessment_id = a.id
                    ) AS test_run_count

                FROM assessments a
                ORDER BY a.created_at DESC, a.id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="Assessment history is temporarily unavailable.",
        ) from None

    items = [
        {
            "assessment_id": row["assessment_id"],
            "name": row["name"],
            "assessment_status": row["assessment_status"],
            "scenario_code": row["scenario_code"],
            "scenario_name": row["scenario_name"],
            "test_run_id": row["test_run_id"],
            "test_run_status": row["test_run_status"],
            "test_run_count": row["test_run_count"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }
        for row in rows
    ]

    return {
        "items": items,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
            "has_more": offset + len(items) < total,
        },
    }
