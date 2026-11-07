"""Read-only assessment history API."""

import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.api.assessments import get_simulation_user
from app.api.reporting import build_assessment_report
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


@router.get(
    "/assessments/{assessment_id}/report",
    summary="Get sanitized assessment report",
    description=(
        "Return an allowlisted assessment report. Raw execution "
        "results and synthetic content are never exposed."
    ),
)
def get_assessment_report(
    assessment_id: str,
    response: Response,
    user: AuthenticatedUser = Depends(get_simulation_user),
) -> dict:
    """Return a sanitized report for the latest assessment test run."""

    set_no_store(response)

    if "assessments.read" not in user.permissions:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to read assessment reports.",
        )

    try:
        with get_connection() as connection:
            row = connection.execute(
                """
                SELECT
                    a.id AS assessment_id,
                    a.name,
                    a.status AS assessment_status,
                    a.created_at,
                    a.started_at AS assessment_started_at,
                    a.completed_at AS assessment_completed_at,

                    tr.id AS test_run_id,
                    tr.status AS test_run_status,
                    tr.started_at AS test_run_started_at,
                    tr.completed_at AS test_run_completed_at,
                    tr.execution_result,

                    tc.scenario_code,
                    tc.name AS scenario_name

                FROM assessments a

                LEFT JOIN test_runs tr
                    ON tr.id = (
                        SELECT latest.id
                        FROM test_runs latest
                        WHERE latest.assessment_id = a.id
                        ORDER BY
                            COALESCE(
                                latest.completed_at,
                                latest.started_at,
                                ''
                            ) DESC,
                            latest.id DESC
                        LIMIT 1
                    )

                LEFT JOIN test_cases tc
                    ON tc.id = tr.test_case_id

                WHERE a.id = ?
                """,
                (assessment_id,),
            ).fetchone()

    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="Assessment report is temporarily unavailable.",
        ) from None

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment report was not found.",
        )

    stored_result = row["execution_result"]

    if (
        row["test_run_id"] is None
        or row["scenario_code"] is None
        or row["scenario_name"] is None
        or row["assessment_status"] != "completed"
        or row["test_run_status"] != "completed"
        or not isinstance(stored_result, str)
        or not stored_result
        or len(stored_result) > 1_000_000
    ):
        raise HTTPException(
            status_code=404,
            detail="A completed report is not available for this assessment.",
        )

    try:
        execution_record = json.loads(stored_result)

        return build_assessment_report(
            assessment={
                "assessment_id": row["assessment_id"],
                "name": row["name"],
                "assessment_status": row["assessment_status"],
                "created_at": row["created_at"],
                "started_at": row["assessment_started_at"],
                "completed_at": row["assessment_completed_at"],
            },
            test_run={
                "test_run_id": row["test_run_id"],
                "test_run_status": row["test_run_status"],
                "started_at": row["test_run_started_at"],
                "completed_at": row["test_run_completed_at"],
            },
            scenario_code=row["scenario_code"],
            scenario_name=row["scenario_name"],
            execution_record=execution_record,
        )

    except (ValueError, TypeError, KeyError, RecursionError):
        raise HTTPException(
            status_code=500,
            detail="The stored assessment report could not be validated.",
        ) from None
